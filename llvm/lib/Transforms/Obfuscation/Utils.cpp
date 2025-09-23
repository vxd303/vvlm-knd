#include "llvm/Transforms/Obfuscation/Utils.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include <cctype>
#include <map>
#include <sstream>

using namespace llvm;

namespace {
using AnnotationParamMap =
    std::map<std::string, std::map<std::string, std::string>>;

AnnotationParamMap parseAnnotationString(StringRef Annotation) {
  AnnotationParamMap Result;

  if (Annotation.empty()) {
    return Result;
  }

  std::string Sanitized;
  Sanitized.reserve(Annotation.size() * 2);
  for (char C : Annotation) {
    if (C == '\0') {
      continue;
    }
    if (C == '(' || C == ')') {
      Sanitized.push_back(' ');
      Sanitized.push_back(C);
      Sanitized.push_back(' ');
    } else if (std::isspace(static_cast<unsigned char>(C))) {
      Sanitized.push_back(' ');
    } else {
      Sanitized.push_back(C);
    }
  }

  SmallVector<StringRef, 16> Tokens;
  StringRef(Sanitized).split(Tokens, ' ', -1, false);

  bool InsideParens = false;
  std::string ActivePass;
  std::string PendingPass;

  for (StringRef Token : Tokens) {
    Token = Token.trim();
    if (Token.empty()) {
      continue;
    }

    if (Token == "(") {
      InsideParens = true;
      if (!PendingPass.empty()) {
        ActivePass = PendingPass;
        PendingPass.clear();
      } else {
        ActivePass.clear();
      }
      continue;
    }

    if (Token == ")") {
      InsideParens = false;
      ActivePass.clear();
      continue;
    }

    if (!InsideParens) {
      PendingPass = Token.lower();
      ActivePass.clear();
      Result[PendingPass];
      continue;
    }

    if (ActivePass.empty()) {
      ActivePass = Token.lower();
      Result[ActivePass];
      continue;
    }

    size_t Eq = Token.find('=');
    if (Eq == StringRef::npos) {
      continue;
    }

    StringRef KeyRef = Token.slice(0, Eq).trim();
    StringRef ValueRef = Token.substr(Eq + 1).trim();
    std::string Key = KeyRef.lower();
    Result[ActivePass][Key] = ValueRef.str();
  }

  return Result;
}
} // namespace

// Shamefully borrowed from ../Scalar/RegToMem.cpp :(
bool valueEscapes(Instruction *Inst) {
  BasicBlock *BB = Inst->getParent();
  for (Value::use_iterator UI = Inst->use_begin(), E = Inst->use_end(); UI != E;
       ++UI) {
    Instruction *I = cast<Instruction>(*UI);
    if (I->getParent() != BB || isa<PHINode>(I)) {
      return true;
    }
  }
  return false;
}

void fixStack(Function *f) {
  // Try to remove phi node and demote reg to stack
  std::vector<PHINode *> tmpPhi;
  std::vector<Instruction *> tmpReg;
  BasicBlock *bbEntry = &*f->begin();

  do {
    tmpPhi.clear();
    tmpReg.clear();

    for (Function::iterator i = f->begin(); i != f->end(); ++i) {

      for (BasicBlock::iterator j = i->begin(); j != i->end(); ++j) {

        if (isa<PHINode>(j)) {
          PHINode *phi = cast<PHINode>(j);
          tmpPhi.push_back(phi);
          continue;
        }
        if (!(isa<AllocaInst>(j) && j->getParent() == bbEntry) &&
            (valueEscapes(&*j) || j->isUsedOutsideOfBlock(&*i))) {
          tmpReg.push_back(&*j);
          continue;
        }
      }
    }
    for (unsigned int i = 0; i != tmpReg.size(); ++i) {
      DemoteRegToStack(*tmpReg.at(i), f->begin()->getTerminator());
    }

    for (unsigned int i = 0; i != tmpPhi.size(); ++i) {
      DemotePHIToStack(tmpPhi.at(i), f->begin()->getTerminator());
    }

  } while (tmpReg.size() != 0 || tmpPhi.size() != 0);
}

std::string readAnnotate(Function *f) {
  std::string annotation = "";

  // Get annotation variable
  GlobalVariable *glob =
      f->getParent()->getGlobalVariable("llvm.global.annotations");

  if (glob != NULL) {
    // Get the array
    if (ConstantArray *ca = dyn_cast<ConstantArray>(glob->getInitializer())) {
      for (unsigned i = 0; i < ca->getNumOperands(); ++i) {
        // Get the struct
        if (ConstantStruct *structAn =
                dyn_cast<ConstantStruct>(ca->getOperand(i))) {
          if (ConstantExpr *expr =
                  dyn_cast<ConstantExpr>(structAn->getOperand(0))) {
            // If it's a bitcast we can check if the annotation is concerning
            // the current function
            if (expr->getOpcode() == Instruction::BitCast &&
                expr->getOperand(0) == f) {
              ConstantExpr *note = cast<ConstantExpr>(structAn->getOperand(1));
              // If it's a GetElementPtr, that means we found the variable
              // containing the annotations
              if (note->getOpcode() == Instruction::GetElementPtr) {
                if (GlobalVariable *annoteStr =
                        dyn_cast<GlobalVariable>(note->getOperand(0))) {
                  if (ConstantDataSequential *data =
                          dyn_cast<ConstantDataSequential>(
                              annoteStr->getInitializer())) {
                    if (data->isString()) {
                      annotation += data->getAsString().lower() + " ";
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return annotation;
}

Optional<int> getAnnotationInt(Function *f, StringRef Pass, StringRef Key) {
  if (!f) {
    return None;
  }

  std::string Annotation = readAnnotate(f);
  if (Annotation.empty()) {
    return None;
  }

  AnnotationParamMap Params = parseAnnotationString(Annotation);
  std::string PassKey = Pass.lower();
  std::string KeyName = Key.lower();

  auto PassIt = Params.find(PassKey);
  if (PassIt == Params.end()) {
    return None;
  }

  auto KeyIt = PassIt->second.find(KeyName);
  if (KeyIt == PassIt->second.end()) {
    return None;
  }

  int Value = 0;
  if (StringRef(KeyIt->second).trim().getAsInteger(10, Value)) {
    return None;
  }

  return Value;
}

bool toObfuscate(bool flag, Function *f, std::string const &attribute) {
  std::string attr = attribute;
  std::string attrNo = "no" + attr;

  // Check if declaration
  if (f->isDeclaration()) {
    return false;
  }

  // Check external linkage
  if (f->hasAvailableExternallyLinkage() != 0) {
    return false;
  }

  // We have to check the nofla flag first
  // Because .find("fla") is true for a string like "fla" or
  // "nofla"
  if (readAnnotate(f).find(attrNo) != std::string::npos) {
    return false;
  }

  // If fla annotations
  if (readAnnotate(f).find(attr) != std::string::npos) {
    return true;
  }

  // If fla flag is set
  if (flag == true) {
    /* Check if the number of applications is correct
    if (!((Percentage > 0) && (Percentage <= 100))) {
      LLVMContext &ctx = llvm::getGlobalContext();
      ctx.emitError(Twine("Flattening application function\
              percentage -perFLA=x must be 0 < x <= 100"));
    }
    // Check name
    else if (func.size() != 0 && func.find(f->getName()) != std::string::npos) {
      return true;
    }

    if ((((int)llvm::cryptoutils->get_range(100))) < Percentage) {
      return true;
    }
    */
    return true;
  }

  return false;
}
