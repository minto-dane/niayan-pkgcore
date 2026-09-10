-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with Interfaces.C;
with MC_Text;
package MC_Command with SPARK_Mode => Off is
   use type Interfaces.C.int;
   Max_Arguments : constant := 48;
   Max_Output : constant := 262_144;
   type Argument_Array is array(Positive range 1..Max_Arguments) of MC_Text.Value;
   type Invocation is record
      Executable : MC_Text.Value;
      Executable_Digest : Digest := Zero_Digest;
      Arguments : Argument_Array;
      Count : Natural range 0..Max_Arguments := 0;
      Pass_Descriptor : Interfaces.C.int := -1; -- readable input at child fd 4; no path re-resolution
      Deadline : Counter := 0; -- receiver-local CLOCK_BOOTTIME milliseconds
      May_Have_External_Effects : Boolean := False;
   end record;
   type Completion is (Not_Started, Exited, Timed_Out, Signalled, Output_Limit, Unknown);
   type Result is record
      State : Completion := Not_Started;
      Exit_Code : Natural range 0..255 := 0;
      Output : Bytes(1..Max_Output) := (others=>0);
      Used : Natural range 0..Max_Output := 0;
   end record;
   procedure Run(C : Invocation; Input : Bytes; R : out Result; Status : out Outcome);
   -- No shell, PATH lookup, inherited environment, stdin terminal or interactive auth.
   -- Opens and hashes an ELF descriptor before fork; execveat consumes that descriptor.
   -- Executable content must remain under an exclusive authorized writer policy
   -- from digest verification through exec; descriptor pinning does not freeze
   -- mutable bytes or the dynamic loader/dependent libraries.
   -- A single-threaded process is mandatory (including native dependencies); no Ada
   -- runtime or allocation is used in the child. No setuid transition is permitted.
   -- Initialize MC_Runtime first; SIGCHLD must be default, with no independent
   -- reaper or SA_NOCLDWAIT. Requires pidfd_open (no unsafe numeric-PID fallback).
   -- The leader is kept unreaped through group cleanup, including normal exit.
   -- Cleanup waits at most one extra second; uninterruptible tasks require the
   -- outer supervisor. Process groups are NOT proof of resource quiescence;
   -- approved helpers must not daemonize/escape their group, and production
   -- service cgroup containment is separate. Remote effects remain UNKNOWN.
end MC_Command;
