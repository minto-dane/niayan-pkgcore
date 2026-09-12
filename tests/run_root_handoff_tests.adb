-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Environment_Variables; with Ada.Text_IO;
with Pkg_Root_Identity;
with MC_Types; use MC_Types; with MC_Clock; with Pkg_Root_Handoff;
procedure Run_Root_Handoff_Tests is
   C : Pkg_Root_Handoff.Session; S : Outcome; Deadline : Counter;
   D : constant Digest := (others => 16#22#);
   Physical : constant Pkg_Root_Identity.Root_Identity := (17, 19, 8, 1);
   ID : constant Identity := (others => 16#11#);
   function Env (Name : String) return Integer is
     (Integer'Value (Ada.Environment_Variables.Value (Name)));
begin
   MC_Clock.Boottime_Milliseconds (Deadline, S); pragma Assert (S = OK);
   Deadline := Deadline + 10_000;
   Pkg_Root_Handoff.Open (C, -1, Deadline, S); pragma Assert (S = Denied);
   Pkg_Root_Handoff.Prepare (C, D, D, D, D, ID, 1024, 1, Deadline, -1, -1, S);
   pragma Assert (S = Denied); Pkg_Root_Handoff.Close (C);
   if Ada.Environment_Variables.Exists ("NIA_TEST_HANDOFF_FD") then
      Deadline := Counter'Value (Ada.Environment_Variables.Value ("NIA_TEST_HANDOFF_DEADLINE"));
      Pkg_Root_Handoff.Open (C, Env ("NIA_TEST_HANDOFF_FD"), Deadline, S); pragma Assert (S = OK);
      Pkg_Root_Handoff.Open (C, Env ("NIA_TEST_HANDOFF_FD"), Deadline, S); pragma Assert (S = Conflict);
      if Ada.Environment_Variables.Exists ("NIA_TEST_REINSPECT") then
         Pkg_Root_Handoff.Reinspect (C, D, D, D, D, ID, 1024, 1, 1234, Deadline + 1, Physical,
            Env ("NIA_TEST_ARCHIVE_FD"), Env ("NIA_TEST_LEASE_FD"), S); pragma Assert (S = Denied);
         Pkg_Root_Handoff.Reinspect (C, D, D, D, D, ID, 1024, 1, 1234, Deadline, Physical,
            Env ("NIA_TEST_ARCHIVE_FD"), Env ("NIA_TEST_LEASE_FD"), S); pragma Assert (S = OK);
         Pkg_Root_Handoff.Prepare (C, D, D, D, D, ID, 1024, 1, Deadline,
            Env ("NIA_TEST_ARCHIVE_FD"), Env ("NIA_TEST_LEASE_FD"), S); pragma Assert (S = Conflict);
      else
      Pkg_Root_Handoff.Prepare (C, D, D, D, D, ID, 1024, 1, Deadline + 1,
         Env ("NIA_TEST_ARCHIVE_FD"), Env ("NIA_TEST_LEASE_FD"), S); pragma Assert (S = Denied);
      Pkg_Root_Handoff.Prepare (C, D, D, D, D, ID, 1024, 1, Deadline,
         Env ("NIA_TEST_ARCHIVE_FD"), Env ("NIA_TEST_LEASE_FD"), S); pragma Assert (S = OK);
      Pkg_Root_Handoff.Prepare (C, D, D, D, D, ID, 1024, 1, Deadline,
         Env ("NIA_TEST_ARCHIVE_FD"), Env ("NIA_TEST_LEASE_FD"), S); pragma Assert (S = Conflict);
      end if;
      Pkg_Root_Handoff.Close (C);
   end if;
   Ada.Text_IO.Put_Line ("PASS root handoff Ada API");
end Run_Root_Handoff_Tests;
