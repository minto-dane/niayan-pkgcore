-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Strings; with Ada.Strings.Fixed;
with Interfaces.C;
with MC_Clock; with MC_FS; with MC_Posix; with MC_SHA256;
package body Pkg_Deb_Container with SPARK_Mode => Off is
   use type MC_FS.Entry_Info; use type MC_FS.Entry_Kind;
   use type Interfaces.C.unsigned; use type Byte;
   function Text (Data : Bytes) return String is
      Result : String (1 .. Data'Length);
   begin
      for I in Data'Range loop
         Result (I - Data'First + 1) := Character'Val (Data (I));
      end loop;
      return Result;
   end Text;
   function Trim (Value : String) return String is
     (Ada.Strings.Fixed.Trim (Value, Ada.Strings.Both));
   procedure Number (Value : String; Base : Positive; Result : out Counter;
                     Status : out Outcome) is
      Token : constant String := Trim (Value); Digit : Counter;
   begin
      Result := 0; Status := Invalid_Input;
      if Token'Length = 0 then return; end if;
      for C of Token loop
         if C not in '0' .. '9' then return; end if;
         Digit := Character'Pos (C) - Character'Pos ('0');
         if Digit >= Counter (Base) or else Result > (Counter'Last - Digit) / Counter (Base) then return; end if;
         Result := Result * Counter (Base) + Digit;
      end loop;
      Status := OK;
   end Number;
   procedure Check_Time (Deadline : Counter; Status : out Outcome) is
      Now : Counter;
   begin
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then Now >= Deadline then Status := Stale; end if;
   end Check_Time;
   procedure Read (File : MC_FS.File; Offset : Counter; Data : out Bytes;
                   Deadline : Counter; Status : out Outcome) is
      Got : Natural;
   begin
      Check_Time (Deadline, Status); if Status /= OK then return; end if;
      MC_FS.Read_At (File, Offset, Data, Got, Status);
      if Status = OK and then Got /= Data'Length then Status := Corrupt; end if;
   end Read;
   procedure Hash_Range (File : MC_FS.File; Offset, Length, Deadline : Counter;
                         Whole : in out MC_SHA256.Context;
                         Content : out Digest; Status : out Outcome) is
      Hash : MC_SHA256.Context := MC_SHA256.Initialize;
      Buffer : Bytes (1 .. 65_536); Position : Counter := 0; Count : Natural;
   begin
      Content := Zero_Digest;
      while Position < Length loop
         Count := Natural (Counter'Min (Buffer'Length, Length - Position));
         Read (File, Offset + Position, Buffer (1 .. Count), Deadline, Status);
         if Status /= OK then return; end if;
         MC_SHA256.Update (Hash, Buffer (1 .. Count));
         MC_SHA256.Update (Whole, Buffer (1 .. Count)); Position := Position + Counter (Count);
      end loop;
      Check_Time (Deadline, Status);
      if Status = OK then Content := MC_SHA256.Finish (Hash); end if;
   end Hash_Range;
   procedure Inspect_File (File : MC_FS.File; Original : Digest; Deadline : Counter;
                           Result : out Envelope; Status : out Outcome) is
      Before, After : MC_FS.Entry_Info; Candidate : Envelope;
      Magic : Bytes (1 .. 8); Header : Bytes (1 .. 60); Padding : Bytes (1 .. 1);
      Position : Counter := 8; Value, Length : Counter; Item : Member;
      Phase : Natural := 0;
      Whole : MC_SHA256.Context := MC_SHA256.Initialize;
      procedure Numeric (First, Last : Positive; Base : Positive := 10) is
      begin Number (Text (Header (First .. Last)), Base, Value, Status); end Numeric;
   begin
      Result := (others => <>);
      MC_FS.Info (File, Before, Status); if Status /= OK then return; end if;
      if Before.Kind /= MC_FS.Regular or else Before.Size < 8 or else Before.Size > Max_Container then
         Status := Invalid_Input; return;
      end if;
      Read (File, 0, Magic, Deadline, Status); if Status /= OK then return; end if;
      if Text (Magic) /= "!<arch>" & ASCII.LF then Status := Corrupt; return; end if;
      MC_SHA256.Update (Whole, Magic);
      Candidate.Original := Original; Candidate.Size := Before.Size;
      while Position < Before.Size loop
         if Candidate.Count = Max_Members then Status := Exhausted; return; end if;
         if Before.Size - Position < 60 then Status := Corrupt; return; end if;
         Read (File, Position, Header, Deadline, Status); if Status /= OK then return; end if;
         MC_SHA256.Update (Whole, Header);
         if Text (Header (59 .. 60)) /= "`" & ASCII.LF then Status := Corrupt; return; end if;
         Numeric (17, 28); if Status /= OK then return; end if;
         Numeric (29, 34); if Status /= OK then return; end if;
         Numeric (35, 40); if Status /= OK then return; end if;
         Numeric (41, 48, 8); if Status /= OK then return; end if;
         Numeric (49, 58); if Status /= OK then return; end if;
         Length := Value; Position := Position + 60;
         if Length > Before.Size - Position then Status := Corrupt; return; end if;
         Item := (others => <>); Item.Offset := Position; Item.Length := Length;
         Item.Header := MC_SHA256.Hash (Header);
         declare
            Raw : constant String := Ada.Strings.Fixed.Trim (Text (Header (1 .. 16)), Ada.Strings.Right);
            Name : constant String := (if Raw'Length > 0 and then Raw (Raw'Last) = '/'
                                       then Raw (Raw'First .. Raw'Last - 1) else Raw);
         begin
            if Name'Length = 0 then Status := Invalid_Input; return; end if;
            for C of Name loop
               if C not in 'a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_' | '-' | '.' then
                  Status := Unsupported; return;
               end if;
            end loop;
            for I in 1 .. Candidate.Count loop
               if MC_Text.Image (Candidate.Items (I).Name) = Name then Status := Corrupt; return; end if;
            end loop;
            MC_Text.Set (Item.Name, Name, Status); if Status /= OK then return; end if;
            if Phase = 0 then
               if Name /= "debian-binary" or else Length not in 4 .. 256 then Status := Unsupported; return; end if;
               declare Data : Bytes (1 .. Natural (Length)); First_Line : Natural := 0; begin
                  Read (File, Position, Data, Deadline, Status); if Status /= OK then return; end if;
                  for I in Data'Range loop
                     if Data (I) = 10 and then First_Line = 0 then First_Line := I - 1; end if;
                     if Data (I) /= 10 and then Data (I) not in 32 .. 126 then Status := Unsupported; return; end if;
                  end loop;
                  if First_Line < 3 or else Data (1) /= Character'Pos ('2') or else Data (2) /= Character'Pos ('.')
                     or else Data (Data'Last) /= 10 then Status := Unsupported; return; end if;
                  -- Minor extensions and extra version lines are retained, not discarded.
                  for I in 3 .. First_Line loop
                     if Data (I) not in Character'Pos ('0') .. Character'Pos ('9') then Status := Unsupported; return; end if;
                  end loop;
                  Number (Text (Data (3 .. First_Line)), 10, Candidate.Minor_Version, Status);
                  if Status /= OK then return; end if;
               end;
               Item.Kind := Version_Info; Phase := 1;
            elsif Phase = 3 then
               Item.Kind := Extension;
            elsif Name (Name'First) = '_' then
               Item.Kind := Extension;
            else
               declare
                  Prefix : constant String := (if Phase = 1 then "control.tar" else "data.tar");
               begin
                  if Name'Length < Prefix'Length or else Name (1 .. Prefix'Length) /= Prefix then
                     Status := Unsupported; return;
                  end if;
                  declare Suffix : constant String := Name (Prefix'Length + 1 .. Name'Last); begin
                     if Suffix = "" then Item.Codec := Uncompressed;
                     elsif Suffix = ".gz" then Item.Codec := Gzip;
                     elsif Suffix = ".xz" then Item.Codec := XZ;
                     elsif Suffix = ".zst" then Item.Codec := Zstd;
                     elsif Phase = 2 and then Suffix = ".bz2" then Item.Codec := Bzip2;
                     elsif Phase = 2 and then Suffix = ".lzma" then Item.Codec := LZMA;
                     else Status := Unsupported; return; end if;
                  end;
                  if Phase = 1 then
                     if Length > Max_Control then Status := Exhausted; return; end if;
                     Item.Kind := Control_Archive; Candidate.Control_Index := Candidate.Count + 1;
                  else Item.Kind := Data_Archive; Candidate.Data_Index := Candidate.Count + 1;
                  end if;
                  Phase := Phase + 1;
               end;
            end if;
         end;
         Hash_Range (File, Position, Length, Deadline, Whole, Item.Content, Status); if Status /= OK then return; end if;
         Candidate.Count := Candidate.Count + 1; Candidate.Items (Candidate.Count) := Item;
         Position := Position + Length;
         if Length mod 2 = 1 then
            if Position = Before.Size then Status := Corrupt; return; end if;
            Read (File, Position, Padding, Deadline, Status); if Status /= OK then return; end if;
            if Padding (1) /= 10 then Status := Corrupt; return; end if;
            MC_SHA256.Update (Whole, Padding);
            Position := Position + 1;
         end if;
      end loop;
      if Phase /= 3 then Status := Corrupt; return; end if;
      MC_FS.Info (File, After, Status); if Status /= OK then return; end if;
      if Before /= After then Status := Conflict; return; end if;
      if MC_SHA256.Finish (Whole) /= Original then Status := Corrupt; return; end if;
      Check_Time (Deadline, Status);
      if Status = OK then Result := Candidate; end if;
   end Inspect_File;
   procedure Inspect (Store : MC_Store.Store; Original : Digest; Deadline : Counter;
                      Result : out Envelope; Status : out Outcome) is
      File : MC_FS.File;
   begin
      Result := (others => <>); Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Check_Time (Deadline, Status); if Status /= OK then return; end if;
      MC_Store.Open_Object (Store, Original, File, Status);
      if Status = OK then Inspect_File (File, Original, Deadline, Result, Status); end if;
      MC_FS.Close (File);
   exception when others => MC_FS.Close (File); Result := (others => <>); Status := IO_Error;
   end Inspect;
   procedure Stage_Member (Store : in out MC_Store.Store; Expected : Envelope;
                          Index : Positive; Deadline : Counter;
                          Content : out Digest; Status : out Outcome) is
      Actual : Envelope; File : MC_FS.File; Writer : MC_Store.Writer;
      Before, After : MC_FS.Entry_Info; Position : Counter := 0;
      Buffer : Bytes (1 .. 65_536); Count : Natural;
      procedure Done is begin MC_Store.Abort_Write (Writer); MC_FS.Close (File); end Done;
   begin
      Content := Zero_Digest; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      if Index > Expected.Count or else Expected.Original = Zero_Digest then Status := Invalid_Input; return; end if;
      Check_Time (Deadline, Status); if Status /= OK then return; end if;
      MC_Store.Open_Object (Store, Expected.Original, File, Status); if Status /= OK then return; end if;
      Inspect_File (File, Expected.Original, Deadline, Actual, Status);
      if Status /= OK then Done; return; end if;
      if Actual /= Expected then Status := Conflict; Done; return; end if;
      MC_FS.Info (File, Before, Status); if Status /= OK then Done; return; end if;
      MC_Store.Begin_Write (Store, Actual.Items (Index).Content, Actual.Items (Index).Length, Writer, Status);
      if Status /= OK then Done; return; end if;
      while Position < Actual.Items (Index).Length loop
         Count := Natural (Counter'Min (Buffer'Length, Actual.Items (Index).Length - Position));
         Read (File, Actual.Items (Index).Offset + Position, Buffer (1 .. Count), Deadline, Status);
         if Status /= OK then Done; return; end if;
         MC_Store.Write_Chunk (Writer, Buffer (1 .. Count), Status); if Status /= OK then Done; return; end if;
         Position := Position + Counter (Count);
      end loop;
      MC_FS.Info (File, After, Status); if Status /= OK then Done; return; end if;
      if Before /= After then Status := Conflict; Done; return; end if;
      Check_Time (Deadline, Status); if Status /= OK then Done; return; end if;
      MC_Store.Finish_Write (Store, Writer, Status);
      if Status = OK then Content := Actual.Items (Index).Content; end if;
      Done;
   exception when others => Done; Content := Zero_Digest; Status := IO_Error;
   end Stage_Member;
end Pkg_Deb_Container;
