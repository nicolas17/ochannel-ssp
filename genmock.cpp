// SPDX-FileCopyrightText: 2020 Nicolás Alvarez <nicolas.alvarez@gmail.com>
//
// SPDX-License-Identifier: Apache-2.0

#include <string>

#include <clang/Tooling/Tooling.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

using namespace clang;
using namespace clang::ast_matchers;
using namespace clang::tooling;
namespace cl = llvm::cl;

DeclarationMatcher funcMatcher = functionDecl().bind("func");

class MockDeclPrinter : public MatchFinder::MatchCallback {
public:
    MockDeclPrinter(llvm::raw_ostream& stream): m_stream(stream) {}

    virtual void run(const MatchFinder::MatchResult &result) {
        if (const FunctionDecl *f = result.Nodes.getNodeAs<clang::FunctionDecl>("func")) {
            auto retType = f->getReturnType();
            m_stream << "MOCK_METHOD(" << retType.getAsString() << ", " << f->getNameAsString() << ", (";
            for (unsigned i=0; i<f->getNumParams(); ++i) {
                if (i != 0) {
                    m_stream << ", ";
                }
                const auto* param = f->getParamDecl(i);
                m_stream << param->getType().getAsString();
            }
            m_stream << "));\n";
        }
    }

private:
    llvm::raw_ostream& m_stream;
};

class ThunkPrinter : public MatchFinder::MatchCallback {
public:
    ThunkPrinter(llvm::raw_ostream& stream): m_stream(stream) {}

    virtual void run(const MatchFinder::MatchResult &result) {
        if (const FunctionDecl *f = result.Nodes.getNodeAs<clang::FunctionDecl>("func")) {
            auto retType = f->getReturnType();
            m_stream << retType.getAsString() << " " << f->getNameAsString() << "(";
            for (unsigned i=0; i<f->getNumParams(); ++i) {
                if (i != 0) {
                    m_stream << ", ";
                }
                const auto* param = f->getParamDecl(i);
                std::string name = param->getIdentifier() ? param->getNameAsString() : ("arg" + std::to_string(i));
                m_stream << param->getType().getAsString() << " " << name;
            }
            m_stream << ") {\n    return g_mock->" << f->getNameAsString() << "(";
            for (unsigned i=0; i<f->getNumParams(); ++i) {
                if (i != 0) {
                    m_stream << ", ";
                }
                const auto* param = f->getParamDecl(i);
                std::string name = param->getIdentifier() ? param->getNameAsString() : ("arg" + std::to_string(i));
                m_stream << name;
            }
            m_stream << ");\n}\n";
        }
    }

private:
    llvm::raw_ostream& m_stream;
};

static cl::OptionCategory generatorCategory("generator options");
static cl::opt<std::string> mockOutputFilename("out-mock", cl::desc("Output filename for mock method declarations"), cl::value_desc("filename"), cl::Required, cl::cat(generatorCategory));
static cl::opt<std::string> thunkOutputFilename("out-thunks", cl::desc("Output filename for thunk function definitions"), cl::value_desc("filename"), cl::Required, cl::cat(generatorCategory));

int main(int argc, const char** argv)
{
    CommonOptionsParser optionsParser(argc, argv, generatorCategory, llvm::cl::Required);

    std::error_code ec;
    llvm::raw_fd_ostream mockFile(mockOutputFilename, ec);
    if (ec) {
        llvm::errs() << "Couldn't open mock output file: " << ec.message() << "\n";
        return 1;
    }
    llvm::raw_fd_ostream thunkFile(thunkOutputFilename, ec);
    if (ec) {
        llvm::errs() << "Couldn't open thunk output file: " << ec.message() << "\n";
        return 1;
    }
    MockDeclPrinter mockPrinter(mockFile);
    ThunkPrinter thunkPrinter(thunkFile);
    MatchFinder finder;
    finder.addMatcher(funcMatcher, &mockPrinter);
    finder.addMatcher(funcMatcher, &thunkPrinter);

    ClangTool tool(optionsParser.getCompilations(),
                   optionsParser.getSourcePathList());

    return tool.run(newFrontendActionFactory(&finder).get());
}
