-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Strings.Fixed; with Ada.Command_Line; with Ada.Streams.Stream_IO; with Ada.Strings.Unbounded;
with Interfaces;
with MC_Types; use MC_Types;
with MC_Clock; with MC_FS; with MC_Runtime; with MC_Store;
with Pkg_Tar_Framing; with Pkg_Tar_Output;
with Test_Support; use Test_Support;
procedure Run_Tar_Output_Tests with SPARK_Mode => Off is
   package T renames Pkg_Tar_Framing; package O renames Pkg_Tar_Output;
   use type Interfaces.Integer_64; use type T.Timestamp; use type Byte;
   Store : MC_Store.Store; File : MC_FS.File; Status : Outcome; Deadline : Counter;
   Value : O.Header; Frames : T.Index; Address : Digest;
   Output : Bytes (1 .. 16_384); Used : Natural;
   Clocks : T.Clock_Array := (1 => (True, -42, 123_456_789), 2 => (True, 123, 456),
      3 => (True, -1, 1), 4 => (True, 0, 42));
   Name : constant String := "etc/raw-" & Character'Val (255) & ".conf";
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   procedure Start is
   begin O.Start (Value, Name, 8#6740#, 4_294_967_294, 1234, 3, Clocks, Status); Need ("start full regular header"); end Start;
   procedure Add (Key, Text : String) is
      Data : Bytes (1 .. Text'Length);
   begin
      for I in Data'Range loop Data (I) := Character'Pos (Text (Text'First + I - 1)); end loop;
      O.Add_Extension (Value, Key, Data, Status); Need ("retain extension");
   end Add;
   procedure Xattr (Name, Text : String) is
      Data : Bytes (1 .. Text'Length);
   begin
      for I in Data'Range loop Data (I) := Character'Pos (Text (Text'First + I - 1)); end loop;
      O.Add_Xattr (Value, Name, Data, Status); Need ("encode raw attribute");
   end Xattr;
   procedure Refuse_Text (Before, After : String; Expected : Outcome) is
      Text : String (1 .. Used); Changed : Bytes := Output; Position : Natural;
   begin
      Expect (Before'Length = After'Length, "bounded format mutation");
      for I in Text'Range loop Text (I) := Character'Val (Output (I)); end loop;
      Position := Ada.Strings.Fixed.Index (Text, Before); Expect (Position /= 0, "format field present");
      for I in After'Range loop Changed (Position + I - After'First) := Character'Pos (After (I)); end loop;
      MC_Store.Put (Store, Changed (1 .. Used + 1_536), Address, Status); Need ("retain isolated format case");
      MC_Store.Open_Object (Store, Address, File, Status); Need ("open isolated format case");
      T.Scan (File, Counter (Used + 1_536), Deadline, Frames, Status); MC_FS.Close (File);
      Expect (Status = Expected and then T.Count (Frames) = 0, "invalid extended field refused without partial frames");
   end Refuse_Text;
   function Contains (Piece : String) return Boolean is
      Text : String (1 .. Used);
   begin
      for I in Text'Range loop Text (I) := Character'Val (Output (I)); end loop;
      return Ada.Strings.Fixed.Index (Text, Piece) /= 0;
   end Contains;
   procedure Archive (Name : String) is
      Total : constant Natural := Used + 512 + 1_024;
      Export : Ada.Streams.Stream_IO.File_Type;
      Data : Ada.Streams.Stream_Element_Array (1 .. Ada.Streams.Stream_Element_Offset (Total));
   begin
      Output (Used + 1 .. Used + 3) := (97, 98, 99);
      MC_Store.Put (Store, Output (1 .. Total), Address, Status); Need ("retain generated tar");
      MC_Store.Open_Object (Store, Address, File, Status); Need ("open generated tar");
      T.Scan (File, Counter (Total), Deadline, Frames, Status); MC_FS.Close (File); Need ("native framing of generated tar");
      Expect (T.Count (Frames) = 1 and then T.At_Index (Frames, 1).Size = 3, "one exact regular entry");
      Expect (Ada.Strings.Unbounded.To_String (T.At_Index (Frames, 1).Names (1)) = Run_Tar_Output_Tests.Name, "raw path bytes retained");
      for I in Clocks'Range loop Expect (T.At_Index (Frames, 1).Clocks (I) = Clocks (I), "full signed clock roundtrip"); end loop;
      for I in 1 .. Total loop Data (Ada.Streams.Stream_Element_Offset (I)) := Ada.Streams.Stream_Element (Output (I)); end loop;
      Ada.Streams.Stream_IO.Create (Export, Ada.Streams.Stream_IO.Out_File, Ada.Command_Line.Argument (2) & "/" & Name & ".tar");
      Ada.Streams.Stream_IO.Write (Export, Data); Ada.Streams.Stream_IO.Close (Export);
   exception when others => if Ada.Streams.Stream_IO.Is_Open (Export) then Ada.Streams.Stream_IO.Close (Export); end if; raise;
   end Archive;
begin
   Expect (Ada.Command_Line.Argument_Count = 2, "store and export directory");
   MC_Runtime.Initialize (Status); Need ("runtime"); MC_Clock.Boottime_Milliseconds (Deadline, Status); Need ("clock"); Deadline := Deadline + 60_000;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("CAS");
   Start; Xattr ("user.binary", ASCII.NUL & Character'Val (255) & Character'Val (127));
   Xattr ("user.empty", ""); Xattr ("user.raw-" & Character'Val (255), "x");
   Xattr ("user.long-" & String'(1 .. 200 => Character'Val (255)), "large-key");
   Add ("SCHILY.fflags", "nodump");
   Add ("SCHILY.acl.access", "user::rwx,user:42:r--,group::r--,mask::r--,other::---");
   O.Finish (Value, Output, Used, Status); Need ("emit exact header");
   Expect (Contains ("mtime=-41.876543211" & ASCII.LF) and then Contains ("ctime=-0.999999999" & ASCII.LF)
      and then Contains ("LIBARCHIVE.creationtime=0.000000042" & ASCII.LF), "independent expected decimal wire values");
   Archive ("normal");
   Refuse_Text ("LIBARCHIVE.xattr.user.raw-%FF=eA", "LIBARCHIVE.xattr.user.raw-%FF=eB", Corrupt);
   Refuse_Text ("LIBARCHIVE.xattr.user.raw-%FF", "LIBARCHIVE.xattr.user.raw-%00", Corrupt);
   Clocks := (1 => (True, Interfaces.Integer_64'First, 0), 2 => (True, Interfaces.Integer_64'First, 1),
      3 => (True, Interfaces.Integer_64'Last, 999_999_999), 4 => (True, -1, 999_999_999));
   Start; O.Finish (Value, Output, Used, Status); Need ("emit full signed range");
   Expect (Contains ("mtime=-9223372036854775808" & ASCII.LF) and then Contains ("atime=-9223372036854775807.999999999" & ASCII.LF)
      and then Contains ("ctime=9223372036854775807.999999999" & ASCII.LF), "full range decimal wire values");
   Archive ("full-range");
   Refuse_Text ("mtime=-9223372036854775808", "mtime=-9223372036854775809", Unsupported);
   Refuse_Text ("atime=-9223372036854775807.999999999", "atime=-9223372036854775808.999999999", Unsupported);
   Refuse_Text ("ctime=9223372036854775807.999999999", "ctime=9223372036854775808.999999999", Unsupported);
   Refuse_Text ("hdrcharset=BINARY", "hdrcharset=BINAQY", Unsupported);
   O.Finish (Value, Output, Used, Status);
   Expect (Status = Invalid_Input and then Used = 0 and then Output = Bytes'(Output'Range => 0), "consumed builder cannot emit again");
   Start; Add ("SCHILY.xattr.user.duplicate", "a"); O.Add_Extension (Value, "SCHILY.xattr.user.duplicate", (1 => 98), Status);
   Expect (Status = Invalid_Input, "duplicate attribute refused"); O.Finish (Value, Output, Used, Status);
   Expect (Status = Invalid_Input and then Used = 0, "failed extension clears builder");
   Start; O.Add_Extension (Value, "mtime", (1 => 48), Status); Expect (Status = Invalid_Input, "extensions cannot replace bound clocks");
   Start; O.Finish (Value, Output (1 .. 1_023), Used, Status);
   Expect (Status = Exhausted and then Used = 0, "short output rejected");
   O.Start (Value, "../escape", 0, 0, 0, 0, Clocks, Status); Expect (Status = Invalid_Input, "relative traversal refused");
   O.Start (Value, "/absolute", 0, 0, 0, 0, Clocks, Status); Expect (Status = Invalid_Input, "absolute archive path refused");
   O.Start (Value, "etc//bad", 0, 0, 0, 0, Clocks, Status); Expect (Status = Invalid_Input, "empty path component refused");
   O.Start (Value, "etc/./bad", 0, 0, 0, 0, Clocks, Status); Expect (Status = Invalid_Input, "dot path component refused");
   O.Start (Value, String'(1 .. 255 => 'a') & "/" & String'(1 .. 255 => 'b'), 0, 0, 0, 0, Clocks, Status);
   Need ("maximum filesystem components accepted");
   O.Start (Value, String'(1 .. 256 => 'a') & "/b", 0, 0, 0, 0, Clocks, Status);
   Expect (Status = Invalid_Input, "oversized parent component refused");
   O.Start (Value, "a/" & String'(1 .. 256 => 'b'), 0, 0, 0, 0, Clocks, Status);
   Expect (Status = Invalid_Input, "oversized final component refused");
   declare Offset_Path : constant String (11 .. 265) := (others => 'c'); begin
      O.Start (Value, Offset_Path, 0, 0, 0, 0, Clocks, Status); Need ("nonunit string origin accepted");
   end;
   O.Start (Value, Name, 8#100644#, 0, 0, 0, Clocks, Status); Expect (Status = Invalid_Input, "kind bits not accepted as permissions");
   Clocks (1).Present := False; O.Start (Value, Name, 0, 0, 0, 0, Clocks, Status);
   Expect (Status = Invalid_Input, "missing mtime is not invented");
   O.Clear (Value); MC_FS.Close (File); MC_Store.Close (Store); Report;
exception when others => O.Clear (Value); MC_FS.Close (File); MC_Store.Close (Store); raise;
end Run_Tar_Output_Tests;
