-- SPDX-License-Identifier: BSD-3-Clause
-- Private CAS only. Synthetic ar envelopes do not qualify their tar contents.
with Ada.Command_Line; with Ada.Strings; with Ada.Strings.Fixed; with Ada.Text_IO;
with Interfaces.C;
with MC_Types; use MC_Types;
with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime;
with MC_SHA256; with MC_Store; with MC_Text;
with Pkg_Deb_Container;
with Test_Support; use Test_Support;
procedure Run_Deb_Container_Tests with SPARK_Mode => Off is
   use type Interfaces.C.unsigned;
   package DC renames Pkg_Deb_Container;
   use type DC.Envelope; use type DC.Compression;
   Store : MC_Store.Store; Status : Outcome; Object, Member_Hash : Digest;
   Result, Saved, Forged : DC.Envelope; Now, Deadline : Counter;
   Buffer : Bytes (1 .. 131_072); Used : Natural := 0;
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   function Data (Value : String) return Bytes is
      B : Bytes (1 .. Value'Length);
   begin
      for I in Value'Range loop B (I - Value'First + 1) := Character'Pos (Value (I)); end loop;
      return B;
   end Data;
   function Header (Name : String; Size : Natural; Slash : Boolean := True) return Bytes is
      H : String (1 .. 60) := (others => ' ');
      N : constant String := Name & (if Slash then "/" else "");
      Size_Image : constant String := Ada.Strings.Fixed.Trim (Natural'Image (Size), Ada.Strings.Both);
   begin
      H (1 .. N'Length) := N; H (17) := '0'; H (29) := '0'; H (35) := '0';
      H (41 .. 46) := "100644"; H (49 .. 48 + Size_Image'Length) := Size_Image;
      H (59 .. 60) := "`" & ASCII.LF; return Data (H);
   end Header;
   function Member (Name, Body_Text : String; Slash : Boolean := True) return Bytes is
     (Header (Name, Body_Text'Length, Slash) & Data (Body_Text) &
      (if Body_Text'Length mod 2 = 1 then Data ("" & ASCII.LF) else Bytes'(1 .. 0 => 0)));
   function Archive (Control : String := "control.tar.xz"; Payload : String := "data.tar.zst") return Bytes is
     (Data ("!<arch>" & ASCII.LF) & Member ("debian-binary", "2.0" & ASCII.LF) &
      Member (Control, "control") & Member (Payload, "payload"));
   procedure Load (Raw : Bytes) is
   begin
      MC_Store.Put (Store, Raw, Object, Status); Need ("store original");
      DC.Inspect (Store, Object, Deadline, Result, Status);
   end Load;
   procedure Rejected (Raw : Bytes; Label_Text : String) is
   begin
      Load (Raw); Expect (Status /= OK, Label_Text);
      Expect (Result = DC.Envelope'(others => <>), "failure never returns partial envelope");
   end Rejected;
begin
   Expect (Ada.Command_Line.Argument_Count in 1 | 3, "fresh CAS, optionally fixture directory and name");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      DC.Inspect (Store, (others => 1), Counter'Last, Result, Status);
      Expect (Status = Denied and then Result = DC.Envelope'(others => <>), "root inspect refused");
      Forged.Original := (others => 1); Forged.Count := 1;
      DC.Stage_Member (Store, Forged, 1, Counter'Last, Member_Hash, Status);
      Expect (Status = Denied and then Member_Hash = Zero_Digest, "root staging refused");
      Report; return;
   end if;
   MC_Clock.Boottime_Milliseconds (Now, Status); Need ("clock"); Deadline := Now + 120_000;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   if Ada.Command_Line.Argument_Count = 3 then
      -- Internal qualification probe, deliberately absent from application mains.
      declare R : MC_FS.Root; F : MC_FS.File; begin
         MC_FS.Open_Root (Ada.Command_Line.Argument (2), R, Status); Need ("fixture directory");
         MC_FS.Open_Read (R, Ada.Command_Line.Argument (3), F, Status); Need ("original fixture");
         MC_Store.Import_File (Store, F, DC.Max_Container, Object, Status); Need ("import original fixture");
         MC_FS.Close (F); MC_FS.Close (R);
         DC.Inspect (Store, Object, Deadline, Result, Status); Need ("inspect actual original DEB envelope");
         Ada.Text_IO.Put_Line ("ORIGINAL " & MC_Hex.Encode (Result.Original) & Counter'Image (Result.Size));
         for I in 1 .. Result.Count loop
            DC.Stage_Member (Store, Result, I, Deadline, Member_Hash, Status); Need ("stage actual member");
            Expect (Member_Hash = Result.Items (I).Content, "actual member digest matches inspection");
            Ada.Text_IO.Put_Line ("MEMBER " & MC_Text.Image (Result.Items (I).Name) & " " &
               MC_Hex.Encode (Member_Hash) & Counter'Image (Result.Items (I).Offset) &
               Counter'Image (Result.Items (I).Length));
         end loop;
      end;
      MC_Store.Close (Store); Report; return;
   end if;
   Load (Archive); Need ("inspect canonical envelope"); Saved := Result;
   Expect (Result.Original = Object and then Result.Count = 3 and then Result.Control_Index = 2
           and then Result.Data_Index = 3 and then Result.Minor_Version = 0, "positions and complete original binding");
   Expect (Result.Items (2).Codec = DC.XZ and then Result.Items (3).Codec = DC.Zstd, "compression declarations");
   Expect (Result.Items (2).Content = MC_SHA256.Hash (Data ("control"))
      and then Result.Items (3).Content = MC_SHA256.Hash (Data ("payload")), "member hashes cover exact encoded bytes");
   DC.Stage_Member (Store, Result, 2, Deadline, Member_Hash, Status); Need ("stage exact member into same CAS");
   MC_Store.Read_Object (Store, Member_Hash, Buffer, Used, Status); Need ("read staged member");
   Expect (Buffer (1 .. Used) = Data ("control"), "original member bytes unchanged");
   DC.Stage_Member (Store, Result, 2, Deadline, Member_Hash, Status); Need ("repeat content-addressed stage");
   MC_Store.Read_Object (Store, Object, Buffer, Used, Status); Need ("read retained original");
   Expect (Buffer (1 .. Used) = Archive, "complete original unchanged by staging");
   Forged := Saved; Forged.Items (2).Offset := Forged.Items (2).Offset + 1;
   DC.Stage_Member (Store, Forged, 2, Deadline, Member_Hash, Status);
   Expect (Status = Conflict and then Member_Hash = Zero_Digest, "untrusted offset rejected after independent reparse");
   Forged := Saved; Forged.Items (2).Content := (others => 17);
   DC.Stage_Member (Store, Forged, 2, Deadline, Member_Hash, Status);
   Expect (Status = Conflict and then Member_Hash = Zero_Digest, "untrusted member digest rejected");
   DC.Stage_Member (Store, Saved, 4, Deadline, Member_Hash, Status);
   Expect (Status = Invalid_Input and then Member_Hash = Zero_Digest, "member index bound");
   DC.Inspect (Store, Saved.Original, 0, Result, Status);
   Expect (Status = Stale and then Result.Count = 0, "expired read deadline");
   DC.Stage_Member (Store, Saved, 2, 0, Member_Hash, Status);
   Expect (Status = Stale and then Member_Hash = Zero_Digest, "expired stage deadline");
   for Encoding in DC.Compression loop
      declare
         Suffix : constant String := (case Encoding is
            when DC.Uncompressed => "", when DC.Gzip => ".gz", when DC.XZ => ".xz",
            when DC.Zstd => ".zst", when DC.Bzip2 => ".bz2", when DC.LZMA => ".lzma");
      begin
         Load (Archive (Payload => "data.tar" & Suffix)); Need ("all declared data compression labels");
         Expect (Result.Items (3).Codec = Encoding, "codec preserved, not decompression qualification");
         if Encoding in DC.Bzip2 | DC.LZMA then
            Rejected (Archive (Control => "control.tar" & Suffix), "legacy control codecs unsupported");
         else
            Load (Archive (Control => "control.tar" & Suffix)); Need ("all current control labels");
         end if;
      end;
   end loop;
   declare
      Extended : constant Bytes := Data ("!<arch>" & ASCII.LF)
        & Member ("debian-binary", "2.7" & ASCII.LF & "extension" & ASCII.LF, False)
        & Member ("_one", "first") & Member ("control.tar", "control", False)
        & Member ("_two", "second") & Member ("data.tar", "payload", False) & Member ("trailer", "extra");
   begin
      Load (Extended); Need ("minor version and ignorable extensions");
      Expect (Result.Minor_Version = 7 and then Result.Count = 6
         and then Result.Control_Index = 3 and then Result.Data_Index = 5, "extensions retained in order");
      DC.Stage_Member (Store, Result, 6, Deadline, Member_Hash, Status); Need ("retain opaque extension in CAS");
      MC_Store.Read_Object (Store, Member_Hash, Buffer, Used, Status); Need ("read opaque extension");
      Expect (Buffer (1 .. Used) = Data ("extra"), "no extension bytes silently discarded");
   end;
   Rejected (Data ("bad"), "truncated archive");
   Rejected (Data ("!<arch>" & ASCII.LF), "missing required members");
   Rejected (Data ("!<arch>" & ASCII.LF) & Member ("debian-binary", "3.0" & ASCII.LF)
      & Member ("control.tar", "") & Member ("data.tar", ""), "incompatible major version");
   Rejected (Data ("!<arch>" & ASCII.LF) & Member ("debian-binary", "2.x" & ASCII.LF)
      & Member ("control.tar", "") & Member ("data.tar", ""), "invalid minor syntax");
   Rejected (Archive & Member ("control.tar.xz", "duplicate"), "duplicate member");
   Rejected (Data ("!<arch>" & ASCII.LF) & Member ("debian-binary", "2.0" & ASCII.LF)
      & Member ("surprise", "opaque") & Member ("control.tar", "") & Member ("data.tar", ""),
      "non-ignorable member before required archives");
   Rejected (Archive (Control => "data.tar", Payload => "control.tar"), "wrong archive order");
   Rejected (Archive (Payload => "data.tar.zip"), "unsupported data codec");
   Rejected (Archive & Member ("../outside", ""), "path-like member name");
   Rejected (Archive & Member ("//", ""), "extended name table");
   Rejected (Archive & Member ("bad" & ASCII.NUL, ""), "NUL in member name");
   declare
      First : constant Bytes := Archive;
      Raw : Bytes (1 .. 4096); Last : Natural := First'Length;
   begin
      Raw (1 .. Last) := First;
      for I in 4 .. DC.Max_Members + 1 loop
         declare Extra : constant Bytes := Member ("extra" &
            Ada.Strings.Fixed.Trim (Natural'Image (I), Ada.Strings.Both), ""); begin
            Raw (Last + 1 .. Last + Extra'Length) := Extra; Last := Last + Extra'Length;
         end;
         Load (Raw (1 .. Last));
         if I <= DC.Max_Members then
            Need ("bounded extensions accepted");
         else
            Expect (Status = Exhausted and then Result.Count = 0, "member count ceiling");
         end if;
      end loop;
   end;
   declare Raw : Bytes := Archive; begin
      Raw (58) := Character'Pos ('X'); Rejected (Raw, "nonnumeric ar metadata");
      Raw := Archive; Raw (68) := 0; Rejected (Raw, "ar header trailer");
      Raw := Archive; Raw (Raw'Last) := 0; Rejected (Raw, "odd member padding");
      Raw := Archive;
      for Cut in 1 .. Raw'Length - 1 loop
         Rejected (Raw (1 .. Cut), "every truncated prefix rejected");
      end loop;
   end;
   declare
      Big : constant String (1 .. 70_001) := (others => 'x');
      Raw : constant Bytes := Data ("!<arch>" & ASCII.LF) & Member ("debian-binary", "2.0" & ASCII.LF)
        & Member ("control.tar", "") & Member ("data.tar", Big);
   begin
      Load (Raw); Need ("multi-chunk member inspection");
      DC.Stage_Member (Store, Result, 2, Deadline, Member_Hash, Status); Need ("empty envelope member CAS copy");
      Expect (Member_Hash = MC_SHA256.Hash (Bytes'(1 .. 0 => 0)), "empty envelope member digest");
      DC.Stage_Member (Store, Result, 3, Deadline, Member_Hash, Status); Need ("multi-chunk CAS copy");
      MC_Store.Read_Object (Store, Member_Hash, Buffer, Used, Status); Need ("read multi-chunk object");
      Expect (Used = Big'Length and then Buffer (1 .. Used) = Data (Big), "all stream chunks preserved");
   end;
   -- Corrupt an isolated CAS object after its address was established. The CAS
   -- reader must reject it before returning a valid envelope.
   declare R : MC_FS.Root; F : MC_FS.File; Name : MC_Text.Value; Info : MC_FS.Entry_Info;
      Hex : constant String := MC_Hex.Encode (Saved.Original);
   begin
      MC_FS.Open_Root (Ada.Command_Line.Argument (1), R, Status, Private_Only => True); Need ("CAS fixture root");
      MC_Text.Set (Name, "objects/" & Hex (1 .. 2) & "/" & Hex (3 .. 64), Status); Need ("fixture object name");
      MC_FS.Remove (R, MC_Text.Image (Name), False, Status); Need ("remove disposable original fixture");
      MC_FS.Create_New (R, MC_Text.Image (Name), F, Status); Need ("fixture replacement handle");
      MC_FS.Write_All (F, Data ("changed"), Status); Need ("fixture corruption");
      MC_FS.Info (F, Info, Status); Need ("fixture metadata"); Info.Mode := 8#400#;
      MC_FS.Set_Metadata (F, Info, Status); Need ("read-only fixture mode");
      MC_FS.Close (F); MC_FS.Close (R);
      DC.Inspect (Store, Saved.Original, Deadline, Result, Status);
      Expect (Status /= OK and then Result.Count = 0, "CAS original hash reverified before inspection");
   end;
   MC_Store.Close (Store); Report;
exception when others => MC_Store.Close (Store); raise;
end Run_Deb_Container_Tests;
