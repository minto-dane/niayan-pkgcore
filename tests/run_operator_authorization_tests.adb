-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Environment_Variables; with Ada.Text_IO;
with MC_Types; use MC_Types; with MC_Clock; with Pkg_Operator_Authorization;
procedure Run_Operator_Authorization_Tests is
   C : Pkg_Operator_Authorization.Session;
   S : Outcome; Deadline : Counter;
   Plan : constant Digest := (others => 16#22#);
   ID : constant Identity := (others => 16#11#);
begin
   MC_Clock.Boottime_Milliseconds (Deadline, S); pragma Assert (S = OK);
   Deadline := Deadline + 10_000;
   Pkg_Operator_Authorization.Check (C, Plan, ID, S); pragma Assert (S = Denied);
   Pkg_Operator_Authorization.Open (C, -1, Plan, ID, Deadline, False, S); pragma Assert (S = Invalid_Input);
   Pkg_Operator_Authorization.Open (C, 0, Zero_Digest, ID, Deadline, False, S); pragma Assert (S = Invalid_Input);
   Pkg_Operator_Authorization.Close (C);
   if Ada.Environment_Variables.Exists ("NIA_TEST_OPERATOR_FD") then
      declare
         FD : constant Integer := Integer'Value (Ada.Environment_Variables.Value ("NIA_TEST_OPERATOR_FD"));
      begin
         Pkg_Operator_Authorization.Open (C, FD, Plan, ID, Deadline, False, S); pragma Assert (S = OK);
         Pkg_Operator_Authorization.Check (C, Plan, ID, S); pragma Assert (S = OK);
         Pkg_Operator_Authorization.Open (C, FD, Plan, ID, Deadline, False, S); pragma Assert (S = Conflict);
         Pkg_Operator_Authorization.Check (C, (others => 16#33#), ID, S); pragma Assert (S = Denied);
         Pkg_Operator_Authorization.Check (C, Plan, ID, S); pragma Assert (S = Denied);
         Pkg_Operator_Authorization.Close (C);
      end;
   end if;
   Ada.Text_IO.Put_Line ("PASS operator authorization Ada API");
end Run_Operator_Authorization_Tests;
