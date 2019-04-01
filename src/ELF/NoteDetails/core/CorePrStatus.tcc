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
#include <algorithm>

#include "LIEF/exception.hpp"
#include "LIEF/utils.hpp"
#include "LIEF/BinaryStream/VectorStream.hpp"

#include "LIEF/ELF/NoteDetails/core/CorePrStatus.hpp"


namespace LIEF {
namespace ELF {

template <typename ELF_T>
void CorePrStatus::parse_(void) {
  using Elf_Prstatus  = typename ELF_T::Elf_Prstatus;
  using uint__        = typename ELF_T::uint;

  const Note::description_t& description = this->description();
  if (description.size() < sizeof(Elf_Prstatus)) {
    return;
  }
  auto&& status = reinterpret_cast<const Elf_Prstatus*>(description.data());

  this->siginfo_ = status->pr_info;
  this->cursig_ = status->pr_cursig;

  this->sigpend_ = status->pr_sigpend;
  this->sighold_ = status->pr_sighold;

  this->pid_  = status->pr_pid;
  this->ppid_ = status->pr_ppid;
  this->pgrp_ = status->pr_pgrp;
  this->sid_  = status->pr_sid;

  //this->utime_  = status->pr_utime;
  //this->stime_  = status->pr_stime;
  //this->cutime_ = status->pr_cutime;
  //this->cstime_ = status->pr_cstime;
  if (this->binary() == nullptr) {
    return;
  }
  const ARCH arch = this->binary()->header().machine_type();

  size_t enum_start = 0;
  size_t enum_end   = 0;
  switch (arch) {
    case ARCH::EM_386:
      {
        enum_start = static_cast<size_t>(REGISTERS::X86_START) + 1;
        enum_end  = static_cast<size_t>(REGISTERS::X86_END);
        break;
      }

    case ARCH::EM_X86_64:
      {
        enum_start = static_cast<size_t>(REGISTERS::X86_64_START) + 1;
        enum_end  = static_cast<size_t>(REGISTERS::X86_64_END);
        break;
      }

    case ARCH::EM_ARM:
      {
        enum_start = static_cast<size_t>(REGISTERS::ARM_START) + 1;
        enum_end  = static_cast<size_t>(REGISTERS::ARM_END);
        break;
      }

    case ARCH::EM_AARCH64:
      {
        enum_start = static_cast<size_t>(REGISTERS::AARCH64_START) + 1;
        enum_end  = static_cast<size_t>(REGISTERS::AARCH64_END);
        break;
      }
  }


  const VectorStream& stream(description);
  stream.setpos(sizeof(Elf_Prstatus));

  for (size_t i = enum_start; i < enum_end; ++i) {
    if (not stream.can_read<uint__>()) {
      break;
    }
    std::cout << std::hex << std::showbase << to_string(static_cast<REGISTERS>(i)) << ": " << stream.read<uint__>() << std::endl;
  }



}

template <typename ELF_T>
void CorePrStatus::build_(void) {
}

} // namespace ELF
} // namespace LIEF
