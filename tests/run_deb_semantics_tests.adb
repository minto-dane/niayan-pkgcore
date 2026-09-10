-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Text_IO; with MC_Types; use MC_Types; with MC_Text;
with Pkg_Deb_Versions; with Pkg_Deb_Semantics; with Pkg_File_Plan;
procedure Run_Deb_Semantics_Tests is
   use Pkg_Deb_Versions; use Pkg_Deb_Semantics;
   N : Requirement; F : Capability; Status : Outcome; Yes : Boolean;
   procedure Set (To : out MC_Text.Value; S : String) is
   begin MC_Text.Set (To, S, Status); pragma Assert (Status = OK); end Set;
begin
   declare
      Shifted : constant String(7..13):="1.0~rc1";
      Empty_Text : String(-1..-2);
      Last_Text : constant String(Integer'Last..Integer'Last):="1";
      Near_End : constant String(Integer'Last-4..Integer'Last-2):="1.0";
   begin
      pragma Assert(Valid(Shifted) and then Compare(Shifted,"1.0")=Older);
      pragma Assert(not Valid(Empty_Text) and then not Valid(Last_Text));
      pragma Assert(Valid(Near_End) and then Compare(Near_End,"1.0-0")=Equal);
      pragma Assert(Valid("2147483647:1") and then Compare("2147483647:1","2147483646:9")=Newer);
   end;
   pragma Assert (not Pkg_File_Plan.Allowed_Path ("var/lib/nia/trust/floor"));
   pragma Assert (not Pkg_File_Plan.Allowed_Path ("etc/nia/keys/release"));
   pragma Assert (Pkg_File_Plan.Allowed_Path ("usr/lib/nia/runtime"));
   pragma Assert (Compare ("1.0~rc1", "1.0") = Older);
   pragma Assert (Compare ("1:0", "999.99") = Newer);
   pragma Assert (Compare ("1.01", "1.1-0") = Equal);
   pragma Assert (Compare ("1a", "1+") = Older);
   pragma Assert (Compare ("1~~", "1~") = Older);
   pragma Assert (Compare ("1:2:3-1", "1:2:3-2") = Older);
   pragma Assert (not Valid ("a1") and not Valid ("1-") and not Valid ("2147483648:1"));
   Set (N.Name, "virtual-api"); Set (N.Version, "2"); N.Operator := At_Least;
   Set (F.Name, "virtual-api"); Set (F.Version, ""); F.Versioned := False;
   Matches (N, F, Yes, Status); pragma Assert (Status = OK and not Yes);
   Set (F.Version, "2"); F.Versioned := True;
   Matches (N, F, Yes, Status); pragma Assert (Status = OK and Yes);
   N.Arch := Any_Architecture; F.Multi := Foreign;
   Matches (N, F, Yes, Status); pragma Assert (Status = OK and not Yes);
   F.Multi := Allowed; Matches (N, F, Yes, Status); pragma Assert (Status = OK and Yes);
   pragma Assert (Requires_Check (Pre_Depends, Before_Unpack));
   pragma Assert (not Requires_Check (Depends, Before_Unpack));
   pragma Assert (Requires_Check (Static_Built_Using, Source_Retention));
   Ada.Text_IO.Put_Line ("DEB semantic unit tests passed; not whole-import qualification");
end Run_Deb_Semantics_Tests;
