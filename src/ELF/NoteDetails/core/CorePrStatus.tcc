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

#include "LIEF/logging++.hpp"


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

  this->utime_.tv_sec  = status->pr_utime.tv_sec;
  this->utime_.tv_usec = status->pr_utime.tv_usec;

  this->stime_.tv_sec  = status->pr_stime.tv_sec;
  this->stime_.tv_usec = status->pr_stime.tv_usec;

  this->cutime_.tv_sec  = status->pr_cutime.tv_sec;
  this->cutime_.tv_usec = status->pr_cutime.tv_usec;

  this->cstime_.tv_sec  = status->pr_cstime.tv_sec;
  this->cstime_.tv_usec = status->pr_cstime.tv_usec;

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

    default:
      {
        LOG(WARNING) << to_string(arch) << " not supported";
      }
  }


  const VectorStream& stream(description);
  stream.setpos(sizeof(Elf_Prstatus) + /* Padding */ 2);

  for (size_t i = enum_start; i < enum_end; ++i) {
    if (not stream.can_read<uint__>()) {
      break;
    }
    this->ctx_[static_cast<REGISTERS>(i)] = stream.read<uint__>();
  }



}

template <typename ELF_T>
void CorePrStatus::build_(void) {
}

} // namespace ELF
} // namespace LIEF
