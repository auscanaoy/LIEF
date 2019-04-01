/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iomanip>
#include <sstream>

#include "LIEF/ELF/hash.hpp"
#include "LIEF/ELF/EnumToString.hpp"

#include "CorePrStatus.tcc"

namespace LIEF {
namespace ELF {

CorePrStatus::CorePrStatus(Note& note):
  NoteDetails::NoteDetails{note}
{}

CorePrStatus CorePrStatus::make(Note& note) {
  CorePrStatus pinfo(note);
  pinfo.parse();
  return pinfo;
}


CorePrStatus::reg_context_t CorePrStatus::reg_context(void) const {
  return {};
}

void CorePrStatus::accept(Visitor& visitor) const {
  visitor.visit(*this);
}

bool CorePrStatus::operator==(const CorePrStatus& rhs) const {
  size_t hash_lhs = Hash::hash(*this);
  size_t hash_rhs = Hash::hash(rhs);
  return hash_lhs == hash_rhs;
}

bool CorePrStatus::operator!=(const CorePrStatus& rhs) const {
  return not (*this == rhs);
}

void CorePrStatus::dump(std::ostream& os) const {
  os << std::left;
}

void CorePrStatus::parse(void) {
  if (this->binary()->type() == ELF_CLASS::ELFCLASS64) {
    this->parse_<ELF64>();
  } else if (this->binary()->type() == ELF_CLASS::ELFCLASS32) {
    this->parse_<ELF32>();
  }
}

void CorePrStatus::build(void) {
  if (this->binary()->type() == ELF_CLASS::ELFCLASS64) {
    this->build_<ELF64>();
  } else if (this->binary()->type() == ELF_CLASS::ELFCLASS32) {
    this->build_<ELF32>();
  }
}

std::ostream& operator<<(std::ostream& os, const CorePrStatus& note) {
  note.dump(os);
  return os;
}

CorePrStatus::~CorePrStatus(void) = default;

} // namespace ELF
} // namespace LIEF
