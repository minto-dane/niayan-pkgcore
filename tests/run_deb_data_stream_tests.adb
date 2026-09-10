-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Directories; with Ada.Text_IO;
with Interfaces.C; with System;
with MC_Types; use MC_Types;
with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime; with MC_SHA256; with MC_Store;
with Pkg_Deb_Container; with Pkg_Deb_Data_Stream;
with Test_Support; use Test_Support;
procedure Run_Deb_Data_Stream_Tests with SPARK_Mode => Off is
   use Interfaces.C; use type System.Address; use type Interfaces.Unsigned_64;
   package DS renames Pkg_Deb_Data_Stream;
   use type DS.Observation;
   function New_Stream (Codec : int; Size, Limit : Interfaces.Unsigned_64; Result : access System.Address) return int
      with Import, Convention => C, External_Name => "nia_deb_stream_new";
   procedure Free_Stream (Handle : System.Address)
      with Import, Convention => C, External_Name => "nia_deb_stream_free";
   function Step (Handle, Input : System.Address; Input_Size : size_t; Consumed : access size_t;
                  Output : System.Address; Capacity : size_t; Produced : access size_t) return int
      with Import, Convention => C, External_Name => "nia_deb_stream_step";
   Store : MC_Store.Store; Media : MC_FS.Root; Status : Outcome;
   Envelope : Pkg_Deb_Container.Envelope; Result : DS.Observation;
   Original, Expected : Digest; Now, Deadline : Counter; Raw_Size : Counter;
   type Positive_Array is array (Positive range <>) of Positive;
   Raw, Encoded : Bytes (1 .. 262_144);
   Raw_Used, Encoded_Used : Natural;
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   procedure Read (Name : String; B : out Bytes; Used : out Natural) is
      F : MC_FS.File;
   begin
      MC_FS.Open_Read (Media, Name, F, Status); Need ("fixture read");
      MC_FS.Read_At (F, 0, B, Used, Status); Need ("fixture bytes"); MC_FS.Close (F);
   end Read;
   procedure Import (Name : String) is
      F : MC_FS.File;
   begin
      MC_FS.Open_Read (Media, Name, F, Status); Need ("fixture open");
      MC_Store.Import_File (Store, F, MC_Store.Max_Object_Size, Original, Status); Need ("original import"); MC_FS.Close (F);
      Pkg_Deb_Container.Inspect (Store, Original, Deadline, Envelope, Status); Need ("original envelope");
   end Import;
   procedure Check_Object is
      F : MC_FS.File; D : Digest; Size : Counter;
   begin
      MC_Store.Open_Object (Store, Result.Expanded, F, Status); Need ("expanded CAS");
      MC_FS.Hash (F, MC_Store.Max_Object_Size, D, Size, Status); Need ("expanded CAS hash"); MC_FS.Close (F);
      Expect (D = Result.Expanded and then Size = Result.Expanded_Size, "complete retained stream");
   end Check_Object;
   procedure Run (Name : String) is
   begin
      Import (Name); DS.Stage (Store, Envelope, MC_Store.Max_Object_Size, Deadline, Result, Status); Need ("stream original data");
      Expect (Result.Original = Original and then Result.Compressed = Envelope.Items (Envelope.Data_Index).Content
         and then Result.Encoded_Size = Envelope.Items (Envelope.Data_Index).Length, "bound original data member");
      Check_Object;
   end Run;
   procedure Rejected (Name : String) is
   begin
      Import (Name); DS.Stage (Store, Envelope, MC_Store.Max_Object_Size, Deadline, Result, Status);
      Expect (Status = Corrupt and then Result = DS.Observation'(others => <>), "bad stream has no partial observation: " & Name);
   end Rejected;
   procedure Fragments (Codec : int; Input_Block, Output_Block : Positive; Empty : Boolean := False) is
      Handle : aliased System.Address := System.Null_Address;
      RC : int; Output : Bytes (1 .. 65_536); Offset, Total : Natural := 0;
      Consumed, Produced : aliased size_t := 0; Hash : MC_SHA256.Context := MC_SHA256.Initialize;
      Limit : constant Interfaces.Unsigned_64 := (if Empty then 0 else Interfaces.Unsigned_64 (Raw_Used));
   begin
      RC := New_Stream (Codec, Interfaces.Unsigned_64 (Encoded_Used), Limit, Handle'Access);
      Expect (RC = 0 and then Handle /= System.Null_Address, "stream creation");
      loop
         RC := Step (Handle, Encoded (Offset + 1)'Address, size_t (Natural'Min (Input_Block, Encoded_Used - Offset)), Consumed'Access,
                     Output'Address, size_t (Output_Block), Produced'Access);
         if RC not in 0 | 1 or else Consumed > size_t (Encoded_Used - Offset) or else Produced > size_t (Output_Block)
            or else (RC = 0 and then Consumed = 0 and then Produced = 0) then
            Free_Stream (Handle); Expect (False, "incremental progress and bounds codec" & int'Image (Codec) & " rc" & int'Image (RC));
         end if;
         Offset := Offset + Natural (Consumed); Total := Total + Natural (Produced);
         MC_SHA256.Update (Hash, Output (1 .. Natural (Produced))); exit when RC = 1;
      end loop;
      Expect (Offset = Encoded_Used and then Total = Natural (Limit)
         and then MC_SHA256.Finish (Hash) = (if Empty then MC_SHA256.Hash (Bytes'(1 .. 0 => 0)) else Expected), "fragment-independent exact stream");
      RC := Step (Handle, System.Null_Address, 0, Consumed'Access, Output'Address, Output'Length, Produced'Access);
      Expect (RC = 2 and then Consumed = 0 and then Produced = 0, "finished decoder cannot restart"); Free_Stream (Handle);
   end Fragments;
begin
   Expect (Ada.Command_Line.Argument_Count in 2 | 3, "fresh CAS, fixtures and optional original filename");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      DS.Stage (Store, Envelope, 0, 0, Result, Status);
      Expect (Status = Denied and then Result = DS.Observation'(others => <>), "root data stream refused before access"); Report; return;
   end if;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("fixture root");
   MC_Clock.Boottime_Milliseconds (Now, Status); Need ("clock"); Deadline := Now + 300_000;
   if Ada.Command_Line.Argument_Count = 3 then
      Run (Ada.Command_Line.Argument (3));
      Ada.Text_IO.Put_Line ("ORIGINAL " & MC_Hex.Encode (Result.Original));
      Ada.Text_IO.Put_Line ("COMPRESSED " & MC_Hex.Encode (Result.Compressed));
      Ada.Text_IO.Put_Line ("EXPANDED " & MC_Hex.Encode (Result.Expanded));
      Ada.Text_IO.Put_Line ("ENCODED_SIZE" & Counter'Image (Result.Encoded_Size));
      Ada.Text_IO.Put_Line ("EXPANDED_SIZE" & Counter'Image (Result.Expanded_Size));
   else
      Read ("payload.raw", Raw, Raw_Used); Expected := MC_SHA256.Hash (Raw (1 .. Raw_Used)); Raw_Size := Counter (Raw_Used);
      for Codec in 0 .. 5 loop
         declare
            Name : constant String := (case Codec is when 0 => "plain", when 1 => "gzip", when 2 => "bzip2", when 3 => "lzma", when 4 => "xz", when 5 => "zstd");
            ID : constant int := (case Codec is when 0 => 0, when 1 => 1, when 2 => 2, when 3 => 5, when 4 => 6, when 5 => 14);
         begin
            Read (Name & ".encoded", Encoded, Encoded_Used);
            for Input_Block of Positive_Array'(1, 7, 65_536) loop
               for Output_Block of Positive_Array'(1, 13, 65_536) loop Fragments (ID, Input_Block, Output_Block); end loop;
            end loop;
            Read ("empty-" & Name & ".encoded", Encoded, Encoded_Used); Fragments (ID, 1, 1, True);
            Run ("valid-" & Name & ".deb");
            Expect (Result.Expanded = Expected and then Result.Expanded_Size = Raw_Size, "golden expanded data");
            DS.Stage (Store, Envelope, Raw_Size, Deadline, Result, Status); Need ("exact output budget including trailer");
            DS.Stage (Store, Envelope, Raw_Size - 1, Deadline, Result, Status);
            Expect (Status = Exhausted and then Result = DS.Observation'(others => <>), "one byte over budget refused");
            if Codec > 0 then
               Rejected ("truncated-" & Name & ".deb"); Rejected ("trailing-" & Name & ".deb");
               Rejected ("concatenated-" & Name & ".deb"); Rejected ("missing-" & Name & ".deb");
               if Codec /= 3 then Rejected ("bad-integrity-" & Name & ".deb"); end if;
            end if;
         end;
      end loop;
      Import ("valid-xz.deb");
      DS.Stage (Store, Envelope, Raw_Size, 0, Result, Status);
      Expect (Status = Stale and then Result = DS.Observation'(others => <>), "expired stream refused");
      Envelope.Items (Envelope.Data_Index).Content := Zero_Digest;
      DS.Stage (Store, Envelope, Raw_Size, Deadline, Result, Status);
      Expect (Status /= OK and then Result = DS.Observation'(others => <>), "forged data envelope rejected");
      Envelope.Data_Index := 0;
      DS.Stage (Store, Envelope, Raw_Size, Deadline, Result, Status);
      Expect (Status = Invalid_Input and then Result = DS.Observation'(others => <>), "missing data index refused");
      DS.Stage (Store, Envelope, MC_Store.Max_Object_Size + 1, Deadline, Result, Status);
      Expect (Status = Exhausted and then Result = DS.Observation'(others => <>), "global output ceiling refused");
      declare
         Handle : aliased System.Address := System.Null_Address; RC : int;
         Output : Bytes (1 .. 1); Consumed, Produced : aliased size_t := 99;
      begin
         Free_Stream (System.Null_Address);
         RC := New_Stream (99, 0, 0, Handle'Access);
         Expect (RC = 4 and then Handle = System.Null_Address, "unknown codec leaves no handle");
         RC := New_Stream (0, 8 * 1024 * 1024 * 1024 + 1, 0, Handle'Access);
         Expect (RC = 3 and then Handle = System.Null_Address, "C encoded ceiling");
         RC := New_Stream (0, 0, 8 * 1024 * 1024 * 1024 + 1, Handle'Access);
         Expect (RC = 3 and then Handle = System.Null_Address, "C expanded ceiling");
         RC := New_Stream (0, 1, 1, Handle'Access); Expect (RC = 0, "invalid-call fixture");
         RC := Step (Handle, System.Null_Address, 1, Consumed'Access, Output'Address, 1, Produced'Access);
         Expect (RC = 2 and then Consumed = 0 and then Produced = 0, "null input with length rejected");
         RC := Step (Handle, Output'Address, 1, Consumed'Access, Output'Address, 1, Produced'Access);
         Expect (RC = 2 and then Consumed = 0 and then Produced = 0, "failed decoder cannot resume"); Free_Stream (Handle);
         RC := Step (System.Null_Address, System.Null_Address, 0, Consumed'Access, Output'Address, 1, Produced'Access);
         Expect (RC = 2 and then Consumed = 0 and then Produced = 0, "null decoder has empty output counts");
         RC := New_Stream (0, 1, 1, Handle'Access); Expect (RC = 0, "capacity fixture");
         RC := Step (Handle, Output'Address, 1, Consumed'Access, Output'Address, 0, Produced'Access);
         Expect (RC = 2 and then Consumed = 0 and then Produced = 0, "zero output capacity rejected"); Free_Stream (Handle);
      end;
   end if;
   MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception when others => MC_FS.Close (Media); MC_Store.Close (Store); raise;
end Run_Deb_Data_Stream_Tests;
