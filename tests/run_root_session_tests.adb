-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Environment_Variables; with Ada.Text_IO;
with MC_Types; use MC_Types; with MC_Clock;
with Pkg_Root_Session; with Pkg_Root_Identity;
procedure Run_Root_Session_Tests is
   use type Pkg_Root_Identity.Root_Identity;
   C : Pkg_Root_Session.Session;
   S : Outcome;
   Deadline : Counter;
   Pin : constant Digest := (others => 16#22#);
   Stage : constant Identity := (others => 16#11#);
   Bank : constant Pkg_Root_Identity.Root_Identity := (Mount_ID => 69, Inode => 2, Device_Major => 8, Device_Minor => 1);
   Empty : constant Pkg_Root_Identity.Root_Identity := (Mount_ID => 0, Inode => 0, Device_Major => 0, Device_Minor => 0);
   procedure Start (Path : String; FD : Integer) is
   begin
      Pkg_Root_Session.Open (C, Path, "12345678-1234-1234-1234-123456789abc",
         Pin, Pin, Pin, Pin, Pin, Stage, 1024, 1, Deadline, Bank, FD, FD, S);
   end Start;
begin
   MC_Clock.Boottime_Milliseconds (Deadline, S); pragma Assert (S = OK);
   Deadline := Deadline + 10_000;
   pragma Assert (not Pkg_Root_Session.Held (C));
   pragma Assert (Pkg_Root_Session.Observation (C) = Empty);
   Start ("relative", 0); pragma Assert (S = Invalid_Input);
   Start ("/unused", -1); pragma Assert (S = Invalid_Input);
   Pkg_Root_Session.Close (C, S); pragma Assert (S = OK);
   if Ada.Environment_Variables.Exists ("NIA_TEST_SESSION_SOCKET") then
      declare
         Path : constant String := Ada.Environment_Variables.Value ("NIA_TEST_SESSION_SOCKET");
         FD : constant Integer := Integer'Value (Ada.Environment_Variables.Value ("NIA_TEST_SESSION_FD"));
      begin
         Start (Path, FD); pragma Assert (S = OK and then Pkg_Root_Session.Held (C));
         pragma Assert (Pkg_Root_Session.Observation (C) = (69, 123, 8, 1));
         Start (Path, FD); pragma Assert (S = Conflict and then Pkg_Root_Session.Held (C));
         Pkg_Root_Session.Observe (C, FD, FD, S); pragma Assert (S = OK);
         Pkg_Root_Session.Close (C, S); pragma Assert (S = OK);
         pragma Assert (not Pkg_Root_Session.Held (C));
         pragma Assert (Pkg_Root_Session.Observation (C) = Empty);
         -- Omit Close on a second session: controlled finalization must EOF.
         declare
            Automatic : Pkg_Root_Session.Session;
         begin
            Pkg_Root_Session.Open (Automatic, Path, "12345678-1234-1234-1234-123456789abc",
               Pin, Pin, Pin, Pin, Pin, Stage, 1024, 1, Deadline, Bank, FD, FD, S);
            pragma Assert (S = OK and then Pkg_Root_Session.Held (Automatic));
         end;
      end;
   end if;
   Ada.Text_IO.Put_Line ("PASS root session Ada API");
end Run_Root_Session_Tests;
