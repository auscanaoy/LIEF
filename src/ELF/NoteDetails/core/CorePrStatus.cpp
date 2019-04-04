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


const CorePrStatus::reg_context_t& CorePrStatus::reg_context(void) const {
  return this->ctx_;
}


const Elf_siginfo& CorePrStatus::siginfo(void) const {
  return this->siginfo_;
}

uint16_t CorePrStatus::current_sig(void) const {
  return this->cursig_;
}

uint64_t CorePrStatus::sigpend(void) const {
  return this->sigpend_;
}

uint64_t CorePrStatus::sighold(void) const {
  return this->sighold_;
}

int32_t CorePrStatus::pid(void) const {
  return this->pid_;
}

int32_t CorePrStatus::ppid(void) const {
  return this->ppid_;
}

int32_t CorePrStatus::pgrp(void) const {
  return this->pgrp_;
}

int32_t CorePrStatus::sid(void) const {
  return this->sid_;
}

Elf64_timeval CorePrStatus::utime(void) const {
  return this->utime_;
}

Elf64_timeval CorePrStatus::stime(void) const {
  return this->stime_;
}

Elf64_timeval CorePrStatus::cutime(void) const {
  return this->cutime_;
}

Elf64_timeval CorePrStatus::cstime(void) const {
  return this->cstime_;
}


void CorePrStatus::siginfo(const Elf_siginfo& siginfo) {
  this->siginfo_ = siginfo;
  this->parse();
}

void CorePrStatus::current_sig(uint16_t current_sig) {
  this->cursig_ = current_sig;
  this->parse();
}

void CorePrStatus::sigpend(uint64_t sigpend) {
  this->sigpend_ = sigpend;
  this->parse();
}

void CorePrStatus::sighold(uint64_t sighold) {
  this->sighold_ = sighold;
  this->parse();
}

void CorePrStatus::pid(int32_t pid) {
  this->pid_ = pid;
  this->parse();
}

void CorePrStatus::ppid(int32_t ppid) {
  this->ppid_ = ppid;
  this->parse();
}

void CorePrStatus::pgrp(int32_t pgrp) {
  this->pgrp_ = pgrp;
  this->parse();
}

void CorePrStatus::sid(int32_t sid) {
  this->sid_ = sid;
  this->parse();
}

void CorePrStatus::utime(Elf64_timeval utime) {
  this->utime_ = utime;
  this->parse();
}

void CorePrStatus::stime(Elf64_timeval stime) {
  this->stime_ = stime;
  this->parse();
}

void CorePrStatus::cutime(Elf64_timeval cutime) {
  this->cutime_ = cutime;
  this->parse();
}

void CorePrStatus::cstime(Elf64_timeval cstime) {
  this->cstime_ = cstime;
  this->parse();
}

void CorePrStatus::reg_context(const reg_context_t& ctx) {
  this->ctx_ = ctx;
  this->parse();
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
  static constexpr size_t WIDTH = 14;
  os << std::left;

  os << std::setw(WIDTH) << std::setfill(' ') << "Siginfo: "<< std::dec;
    dump(os, this->siginfo());
  os << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Current Signal: "<< std::dec
     << this->current_sig() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Pending signal: "<< std::dec
     << this->sigpend() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Signal held: "<< std::dec
     << this->sighold() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "PID: "<< std::dec
     << this->pid() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "PPID: "<< std::dec
     << this->ppid() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "PGRP: "<< std::dec
     << this->pgrp() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "SID: "<< std::dec
     << this->sid() << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "utime: "<< std::dec;
    dump(os, this->utime());
  os << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "stime: "<< std::dec;
    dump(os, this->stime());
  os << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "cutime: "<< std::dec;
    dump(os, this->cutime());
  os << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "cstime: "<< std::dec;
    dump(os, this->cstime());
  os << std::endl;

  os << std::setw(WIDTH) << std::setfill(' ') << "Registers: "<< std::dec;
    dump(os, this->reg_context());
  os << std::endl;

}

std::ostream& CorePrStatus::dump(std::ostream& os, const Elf64_timeval& time) {
  os << std::dec;
  os << time.tv_sec << ":" << time.tv_usec;
  return os;
}

std::ostream& CorePrStatus::dump(std::ostream& os, const Elf_siginfo& siginfo) {
  return os;
}

std::ostream& CorePrStatus::dump(std::ostream& os, const reg_context_t& ctx) {
  return os;
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
