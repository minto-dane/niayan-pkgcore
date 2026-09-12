-- SPDX-License-Identifier: BSD-3-Clause
-- Private root child: a fresh native observation for each ordered pipe request.
with Ada.Command_Line;
with Interfaces.C; with MC_Posix;
with MC_Types; use MC_Types;
with MC_Runtime; with MC_Hex; with MC_Clock; with MC_Codec;
with Pkg_Operator_Authorization;
procedure Pkg_Operator_Guard with SPARK_Mode => Off is
   use Ada.Command_Line; use type Wide;
   use type Interfaces.C.int; use type Interfaces.C.long; use type Interfaces.C.unsigned;
   Context : Pkg_Operator_Authorization.Session;
   Plan : Digest := Zero_Digest; Request : Identity := Zero_Identity;
   Deadline, Before, After : Counter := 0;
   Status : Outcome := Invalid_Input;
   Peer : Integer := -1;
   Sequence : Natural range 0 .. 1_200 := 0;
   Input : aliased Bytes (1 .. 8) := (others => 0);
   Output : aliased Bytes (1 .. 32) := (others => 0);
   Count : Interfaces.C.long;
   Interactive : Boolean := False;
   procedure Nonblocking (FD : MC_Posix.FD) is
      Flags : constant Interfaces.C.int := MC_Posix.Dup (FD, 3, 0); -- F_GETFL
   begin
      if Flags < 0 or else MC_Posix.Dup (FD, 4, Interfaces.C.int
         (Interfaces.C.unsigned (Flags) or Interfaces.C.unsigned (MC_Posix.O_NONBLOCK))) /= 0
      then raise Program_Error; end if; -- F_SETFL, private pipe endpoints only
   end Nonblocking;
begin
   if Argument_Count /= 5 then Set_Exit_Status (64); return; end if;
   if Argument (5) = "--interactive" then Interactive := True;
   elsif Argument (5) /= "--noninteractive" then Set_Exit_Status (64); return; end if;
   Peer := Integer'Value (Argument (1)); Deadline := Counter'Value (Argument (4));
   if Peer < 3 then Set_Exit_Status (64); return; end if;
   MC_Runtime.Initialize (Status);
   if Status = OK then MC_Hex.Decode (Argument (2), Plan, Status); end if;
   if Status = OK then MC_Hex.Decode (Argument (3), Request, Status); end if;
   if Status = OK then
      Pkg_Operator_Authorization.Open (Context, Peer, Plan, Request, Deadline, Interactive, Status);
   end if;
   if Status /= OK then Pkg_Operator_Authorization.Close (Context); Set_Exit_Status (2); return; end if;
   Nonblocking (0); Nonblocking (1);
   -- Deadline is also checked inside the native SDK. The parent bounds each
   -- observation and kills this child on a stalled native call or pipe wait.
   for Attempt in 1 .. 12_000 loop
      MC_Clock.Boottime_Milliseconds (Before, Status);
      exit when Status /= OK or else Before >= Deadline;
      Count := MC_Posix.Read (0, Input'Address, 8);
      if Count = -1 and then MC_Posix.Errno_Location.all = MC_Posix.EAGAIN then
         delay 0.01;
      else
         exit when Count /= 8 or else Sequence = 1_200;
         exit when MC_Codec.U64 (Input, 1) /= Wide (Sequence + 1);
         Sequence := Sequence + 1;
         MC_Clock.Boottime_Milliseconds (Before, Status);
         exit when Status /= OK or else Before >= Deadline;
         Pkg_Operator_Authorization.Check (Context, Plan, Request, Status);
         exit when Status /= OK;
         MC_Clock.Boottime_Milliseconds (After, Status);
         exit when Status /= OK or else After < Before or else After >= Deadline;
         Output (1 .. 8) := (78, 73, 65, 79, 80, 82, 48, 49); -- NIAOPR01
         MC_Codec.Put64 (Output, 9, Wide (Sequence));
         MC_Codec.Put64 (Output, 17, Wide (Before)); MC_Codec.Put64 (Output, 25, Wide (After));
         exit when MC_Posix.Write (1, Output'Address, 32) /= 32;
      end if;
   end loop;
   Pkg_Operator_Authorization.Close (Context);
   Set_Exit_Status (2); -- EOF/expiry/cancellation is not an authorization result.
exception when others =>
   Pkg_Operator_Authorization.Close (Context); Set_Exit_Status (2);
end Pkg_Operator_Guard;
