/*-
 * Copyright 2016 Vsevolod Stakhov
 * Copyright 2018 Sergey Kandaurov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/Tooling/Tooling.h"
#include <unordered_map>
#include <unordered_set>
#include <sstream>

using namespace clang;
using arg_handler_t = bool (*) (const Expr *, struct PrintfArgChecker *);

struct PrintfArgChecker {
private:
	arg_handler_t handler;
public:
	int width;
	int precision;
	ASTContext *past;
	CompilerInstance *pci;

	PrintfArgChecker(arg_handler_t _p, ASTContext *_ast,
		CompilerInstance *_ci) : handler(_p), past(_ast), pci(_ci)
	{
		width = 0;
		precision = 0;
	}

	virtual ~PrintfArgChecker() {}

	bool operator() (const Expr *e)
	{
		return handler(e, this);
	}

	bool valid()
	{
		return handler != nullptr;
	}
};

class FindNamedClassVisitor : public RecursiveASTVisitor<FindNamedClassVisitor> {
public:
	FindNamedClassVisitor(ASTContext *Context, CompilerInstance &CI)
		: Context(Context), CI(&CI) {}

	bool VisitCallExpr(CallExpr *E) {
		Decl *decl = E->getCalleeDecl();
		if (decl == NULL) {
			return true;
		}

		NamedDecl *callee = dyn_cast<NamedDecl>(decl);
		if (callee == NULL) {
			llvm::errs() << "Bad callee\n";
			return false;
		}

		std::string fname = callee->getQualifiedNameAsString();
		std::unordered_map<std::string, unsigned>::iterator iter =
			printf_functions.find(fname);

		if (iter == printf_functions.end())
			return true;

		unsigned pos = iter->second;
		Expr **args = E->getArgs();
		Expr *arg = args[pos];

		if (!arg->isEvaluatable(*Context))
			return true;

		Expr::EvalResult r;

		if (!arg->EvaluateAsRValue(r, *Context))
			return false;

		// njs_error_fmt_new permits NULL fmt
		const APValue::LValueBase base =
			r.Val.getLValueBase().get<const Expr *>();
		if (!base)
			return false;

		const StringLiteral *qval = dyn_cast<StringLiteral>(
			r.Val.getLValueBase().get<const Expr *>());
		if (!qval)
			return false;

		std::shared_ptr<std::vector<PrintfArgChecker>> parsers =
			genParsers(qval->getString(), E);

		if (!parsers)
			return true;

		if (parsers->size() != E->getNumArgs() - (pos + 1)) {
			std::ostringstream err_buf;
			err_buf << "number of arguments for " << fname
				<< " mismatches query string '"
				<< qval->getString().str()
				<< "', expected " << parsers->size()
				<< " args, got " <<
				(E->getNumArgs() - (pos + 1)) << " args";
			print_error(err_buf.str(), E, this->CI);

			return false;
		}

		for (unsigned i = pos + 1; i < E->getNumArgs(); i++) {
			Expr *arg = args[i];

			if (arg && !parsers->at(i - (pos + 1))(arg))
				return false;
		}

		return true;
	}

private:
	ASTContext *Context;
	CompilerInstance *CI;

	std::unordered_map<std::string, unsigned> printf_functions = {
		{"njs_sprintf",			2},
		{"njs_dprintf",			1},
		{"njs_error_fmt_new",		3},
		{"njs_parser_lexer_error",	2},
		{"njs_parser_node_error",	3},
	};

	std::unordered_map<char, arg_handler_t> arg_handlers = {
		{'b',			ngx_int_arg_handler	},
		{'c',			char_arg_handler	},
		{'D',			int32_arg_handler	},
		{'d',			int_arg_handler		},
		{'f',			double_arg_handler	},
		{'i',			ngx_int_arg_handler	},
		{'L',			int64_arg_handler	},
		{'l',			long_arg_handler	},
		{'n',			(arg_handler_t)nullptr	},
		{'O',			offt_arg_handler	},
		{'p',			pointer_arg_handler	},
		{'s',			cstring_arg_handler	},
		{'T',			time_arg_handler	},
		{'V',			ngx_str_arg_handler	},
		{'Z',			(arg_handler_t)nullptr	},
		{'z',			size_arg_handler	},
	};

	std::unique_ptr<PrintfArgChecker>
	parseFlags(const std::string &flags, const Expr *e)
	{
		const char type = flags.back();

		if (arg_handlers.find(type) == arg_handlers.end()) {
			print_error(std::string("unknown format: ") + type,
				e, this->CI);
			return nullptr;
		}

		return std::make_unique<PrintfArgChecker>(
			arg_handlers.find(type)->second,
			this->Context, this->CI);
	}

	std::shared_ptr<std::vector<PrintfArgChecker>>
	genParsers(const StringRef query, const Expr *e)
	{
		enum {
			ignore_chars = 0,
			read_percent,
			read_width,
			read_precision,
			read_arg
		} state = ignore_chars;
		int width, precision;
		std::string flags;

		std::shared_ptr<std::vector<PrintfArgChecker>> res =
			std::make_shared<std::vector<PrintfArgChecker>>();

		for (const char *citer = query.begin();
			citer != query.end();
			++citer)
		{
			char c = *citer;

			switch (state) {
			case ignore_chars:
				if (c == '%') {
					state = read_percent;
					flags.clear();
					width = precision = 0;
				}
				break;

			case read_percent:
				if (isdigit(c)) {
					state = read_width;
					width = c - '0';

				} else if (c == '.') {
					state = read_precision;
					precision = c - '0';

				} else if (c == '*') {
					/* %*s - need integer argument */
					res->emplace_back(width_arg_handler,
						this->Context, this->CI);

					if (*std::next(citer) == '.') {
						++citer;
						state = read_precision;

					} else {
						state = read_arg;
					}

				} else if (c == '%') {
					/* Percent character, ignore */
					state = ignore_chars;

				} else {
					// Rewind iter
					--citer;
					state = read_arg;
				}
				break;

			case read_width:
				if (isdigit(c)) {
					width *= 10;
					width += c - '0';

				} else if (c == '.') {
					state = read_precision;
					precision = c - '0';

				} else {
					// Rewind iter
					--citer;
					state = read_arg;
				}
				break;

			case read_precision:
				if (isdigit(c)) {
					precision *= 10;
					precision += c - '0';

				} else if (c == '*') {
					res->emplace_back(width_arg_handler,
						this->Context, this->CI);
					state = read_arg;

				} else {
					// Rewind iter
					--citer;
					state = read_arg;
				}
				break;

			case read_arg:
				if (arg_handlers.find(c) == arg_handlers.end()
					&& isalpha(c))
				{
					flags.push_back(c);
					break;
				}

				if (isalpha(c)) {
					flags.push_back(c);
				}

				std::unique_ptr<PrintfArgChecker> handler =
					parseFlags(flags, e);
				if (!handler) {
					return nullptr;
				}

				if (handler->valid()) {
					PrintfArgChecker handler_copy = *handler;
					handler_copy.precision = precision;
					handler_copy.width = width;
					res->emplace_back(std::move(handler_copy));
				}

				if (c == '%')
					state = read_percent;
				else
					state = ignore_chars;

				flags.clear();
				width = precision = 0;

				break;
			}
		}

		if (state == read_arg) {
			std::unique_ptr<PrintfArgChecker> handler =
				parseFlags(flags, e);

			if (!handler)
				return nullptr;

			PrintfArgChecker handler_copy = *handler;
			handler_copy.precision = precision;
			handler_copy.width = width;
			res->emplace_back(std::move(handler_copy));
		}

		return res;
	}

	/* Type handlers */
	static bool
	char_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_builtin_type(arg, ctx,
			{BuiltinType::Kind::UChar,
			 BuiltinType::Kind::SChar,
			 // Because of char -> int propagation
			 BuiltinType::Kind::Int},
			"%c");
	}

	static bool
	int32_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		std::vector<BuiltinType::Kind> v;

		if (sizeof(int32_t) == sizeof(long)) {
			v.push_back(BuiltinType::Kind::ULong);
			v.push_back(BuiltinType::Kind::Long);
		}
		if (sizeof(int32_t) == sizeof(int)) {
			v.push_back(BuiltinType::Kind::UInt);
			v.push_back(BuiltinType::Kind::Int);
		}

		return check_builtin_type(arg, ctx, v, "%D");
	}

	static bool
	int_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_builtin_type(arg, ctx,
			{BuiltinType::Kind::UInt,
			 BuiltinType::Kind::Int},
			"%d");
	}

	static bool
	double_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_builtin_type(arg, ctx,
			{BuiltinType::Kind::Double},
			"%f");
	}

	static bool
	ngx_int_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_builtin_type(arg, ctx,
			{BuiltinType::Kind::UInt,
			 BuiltinType::Kind::Int},
			"%i or %b");
	}

	static bool
	int64_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		std::vector<BuiltinType::Kind> v;

		if (sizeof(int64_t) == sizeof(long long)) {
			v.push_back(BuiltinType::Kind::ULongLong);
			v.push_back(BuiltinType::Kind::LongLong);
		}
		if (sizeof(int64_t) == sizeof(long)) {
			v.push_back(BuiltinType::Kind::ULong);
			v.push_back(BuiltinType::Kind::Long);
		}

		return check_builtin_type(arg, ctx, v, "%L");
	}

	static bool
	long_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_builtin_type(arg, ctx,
			{BuiltinType::Kind::ULong,
			 BuiltinType::Kind::Long},
			"%l");
	}

	static bool
	offt_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		if (sizeof(long) == sizeof(int64_t)) {
			return check_builtin_type(arg, ctx,
				{BuiltinType::Kind::Long},
				"%O");

		} else if (sizeof(long) == sizeof(int32_t)) {
			return check_builtin_type(arg, ctx,
				{BuiltinType::Kind::LongLong},
				"%O");
		}

		assert(0);
	}

	static bool
	pointer_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		const Type *type = arg->getType().split().Ty;

		if (type->isPointerType())
			return true;

		print_error(std::string("bad pointer argument for %p: ") +
			arg->getType().getAsString(), arg, ctx->pci);
		return false;
	}

	static bool
	cstring_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		const Type *type = arg->getType().split().Ty;

		if (!type->isPointerType()) {
			print_error(std::string ("bad string argument for %s: ") +
					arg->getType().getAsString(),
					arg, ctx->pci);
			return false;
		}

		const Type *ptr_type = type->getPointeeType().split().Ty;

		if (ptr_type->isCharType())
			return true;

		const Type *desugared_type = ptr_type->getUnqualifiedDesugaredType();
		const Type *desugared_ptr_type = type->getUnqualifiedDesugaredType();

		if (!desugared_type || (!desugared_type->isCharType() &&
			!desugared_ptr_type->isVoidPointerType()))
		{
			if (desugared_type) {
				desugared_type->dump();
			}
			print_error(std::string("bad string argument for %s: ") +
				arg->getType().getAsString(),
				arg, ctx->pci);
			return false;
		}

		return true;
	}

	static bool
	time_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_builtin_type(arg, ctx,
			{BuiltinType::Kind::ULong,
			 BuiltinType::Kind::Long},
			"%T");
	}

	static bool
	ngx_str_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		return check_struct_type(arg, ctx,
			{"njs_str_t *",
			 "const njs_str_t *"},
			"%V");
	}

	static bool
	size_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		if (sizeof(size_t) == sizeof(uint64_t)) {
			return check_builtin_type(arg, ctx,
				{BuiltinType::Kind::ULong,
				 BuiltinType::Kind::Long},
				"%z");

		} else if (sizeof(size_t) == sizeof(uint32_t)) {
			return check_builtin_type(arg, ctx,
				{BuiltinType::Kind::UInt,
				 BuiltinType::Kind::Int},
				"%z");
		}

		assert(0);
	}

	static bool
	width_arg_handler(const Expr *arg, struct PrintfArgChecker *ctx)
	{
		if (sizeof(size_t) == sizeof(uint64_t)) {
			return check_builtin_type(arg, ctx,
				{BuiltinType::Kind::ULong,
				 BuiltinType::Kind::Long},
				"%*s width");

		} else if (sizeof(size_t) == sizeof(uint32_t)) {
			return check_builtin_type(arg, ctx,
				{BuiltinType::Kind::UInt,
				 BuiltinType::Kind::Int},
				"%*s width");
		}

		assert(0);
	}

	static bool
	check_builtin_type(const Expr *arg, struct PrintfArgChecker *ctx,
		const std::vector <BuiltinType::Kind> &k, const std::string &fmt)
	{
		const Type *type = arg->getType().split().Ty;
		const Type *desugared_type = type->getUnqualifiedDesugaredType();

		if (!desugared_type->isBuiltinType()) {
			print_error(std::string ("not a builtin type for ") +
					fmt + " arg: " +
					arg->getType().getAsString(),
					arg, ctx->pci);
			return false;
		}

		const BuiltinType *builtin_type =
			dyn_cast<BuiltinType>(desugared_type);
		BuiltinType::Kind kind = builtin_type->getKind();

		for (BuiltinType::Kind kk : k) {
			if (kind == kk)
				return true;
		}

		std::string resolved = builtin_type->getNameAsCString(
			ctx->past->getPrintingPolicy());
		print_error(std::string("bad argument for ") + fmt + " arg: " +
			arg->getType().getAsString() + ", resolved as: " +
			resolved, arg, ctx->pci);
		return false;
	}

	static bool
	check_struct_type(const Expr *arg, struct PrintfArgChecker *ctx,
		const std::vector<std::string> &k, const std::string &fmt)
	{
		const Type *type = arg->getType().split().Ty;

		if (!type->isPointerType()) {
			print_error(std::string("bad argument for ") + fmt
					+ ": " + arg->getType().getAsString(),
					arg, ctx->pci);
			return false;
		}

		const Type *ptr_type = type->getPointeeType().split().Ty;
		const Type *desugared_type =
			ptr_type->getUnqualifiedDesugaredType();
		std::string str =
			arg->getType().getCanonicalType().getAsString();

		if (!desugared_type->isRecordType()) {
			if (str == "void *")
				return true;

			print_error(std::string("not a record type for ")
				+ fmt + " arg: " + str, arg, ctx->pci);
			return false;
		}

		for (std::string kk : k) {
			if (str == kk)
				return true;
		}

		print_error(std::string("bad argument for ")
			+ fmt + " arg: " + arg->getType().getAsString(),
			arg, ctx->pci);
		return false;
	}

	static void
	print_error(const std::string &err, const Expr *e,
		CompilerInstance *ci)
	{
		SourceLocation loc = e->getExprLoc();
		DiagnosticsEngine &diag = ci->getDiagnostics();
		unsigned id = diag.getCustomDiagID(DiagnosticsEngine::Error, "%0");
		diag.Report(loc, id) << err;
	}
};

class FindNamedClassConsumer : public ASTConsumer {
	CompilerInstance &Instance;
public:
	FindNamedClassConsumer(CompilerInstance &Instance)
		: Instance(Instance) {}

	void HandleTranslationUnit(ASTContext &Context) override {
		FindNamedClassVisitor v(&Context, Instance);
		v.TraverseDecl(Context.getTranslationUnitDecl());
	}
};

class FindNamedClassAction : public PluginASTAction {
protected:
	std::unique_ptr<ASTConsumer> CreateASTConsumer(
		CompilerInstance &CI, llvm::StringRef) override {
		return std::make_unique<FindNamedClassConsumer>(CI);
	}
	bool ParseArgs(const CompilerInstance &CI,
		const std::vector<std::string> &args) override
	{
		return true;
	}
	void PrintHelp(llvm::raw_ostream& ros) {}
};

static FrontendPluginRegistry::Add<FindNamedClassAction> X(
	"ngx-ast", "my plugin description");
