-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Command_Line; with Ada.Directories; with Ada.Text_IO;
with Interfaces.C;
with MC_Types; use MC_Types;
with MC_Clock; with MC_FS; with MC_Hex; with MC_Posix; with MC_Runtime;
with MC_SHA256; with MC_Store; with MC_Text;
with Pkg_Deb_Container; with Pkg_Deb_Control;
with Test_Support; use Test_Support;
procedure Run_Deb_Control_Tests with SPARK_Mode => Off is
   use type Interfaces.C.unsigned; use type Word; use type Interfaces.Integer_64;
   package DC renames Pkg_Deb_Container; package CT renames Pkg_Deb_Control;
   use type CT.Inventory; use type CT.Entry_Kind;
   Store : MC_Store.Store; Media : MC_FS.Root; Status : Outcome;
   Object : Digest; Envelope : DC.Envelope; Result, Saved : CT.Inventory;
   Now, Deadline : Counter; Buffer : Bytes (1 .. 4096); Used : Natural;
   Control_Text : constant String := "Package: fixture" & ASCII.LF & "Version: 1:2.0-1" & ASCII.LF
      & "Architecture: all" & ASCII.LF & "Maintainer: Fixture <fixture@example.invalid>" & ASCII.LF & "Description: fixture only" & ASCII.LF & " continuation" & ASCII.LF
      & "X-Preserved: opaque" & ASCII.LF;
   procedure Need (Label_Text : String) is
   begin Expect (Status = OK, Label_Text & Outcome'Image (Status)); end Need;
   function Data (S : String) return Bytes is
      B : Bytes (1 .. S'Length);
   begin
      for I in S'Range loop B (I - S'First + 1) := Character'Pos (S (I)); end loop;
      return B;
   end Data;
   procedure Inspect (Filename : String) is
      F : MC_FS.File;
   begin
      MC_FS.Open_Read (Media, Filename, F, Status); Need ("open fixture " & Filename);
      MC_Store.Import_File (Store, F, DC.Max_Container, Object, Status); Need ("import fixture"); MC_FS.Close (F);
      DC.Inspect (Store, Object, Deadline, Envelope, Status); Need ("fixture ar envelope");
      CT.Stage (Store, Envelope, Deadline, Result, Status);
   end Inspect;
   procedure Run (Name : String; Acceptable : Boolean) is
   begin
      Inspect (Name & ".deb");
      if not Acceptable then
         Expect (Status /= OK, "rejected control fixture " & Name);
         Expect (Result = CT.Inventory'(others => <>), "no partial inventory " & Name); return;
      end if;
      Need ("accepted control fixture " & Name);
      Expect (Result.Original = Object and then Result.Archive = Envelope.Items (Envelope.Control_Index).Content,
         "control inventory binds original and compressed archive");
      Expect (Result.Count = 4 and then Result.Control_Index = 2, "all control members retained");
      Expect (Result.Entries (1).Kind = CT.Directory and then MC_Text.Image (Result.Entries (1).Name) = ".",
         "optional root directory retained");
      Expect (Result.Entries (2).UID = 1001 and then Result.Entries (2).GID = 1002
         and then Result.Entries (2).Mode = 8#640# and then Result.Entries (2).Modified_Seconds = 1788739200,
         "original numeric metadata preserved without ownership application");
      Expect (MC_Text.Image (Result.Entries (2).User_Name) = "fixture-user"
         and then MC_Text.Image (Result.Entries (2).Group_Name) = "fixture-group", "symbolic owners retained");
      MC_Store.Read_Object (Store, Result.Entries (2).Content, Buffer, Used, Status); Need ("read retained control");
      Expect (Buffer (1 .. Used) = Data (Control_Text), "unfolded and unknown original fields retained as bytes");
      Expect (Result.Entries (3).Content = MC_SHA256.Hash (Data ("#!/bin/sh" & ASCII.LF & "exit 97" & ASCII.LF))
         and then Result.Entries (3).Mode = 8#755#, "script retained without execution");
      MC_Store.Read_Object (Store, Result.Entries (4).Content, Buffer, Used, Status); Need ("read unknown control file");
      Expect (Buffer (1 .. Used) = Data ("preserve" & ASCII.NUL & "all" & Character'Val (255) & "bytes"),
         "unknown binary control data retained");
      Saved := Result;
   end Run;
begin
   Expect (Ada.Command_Line.Argument_Count in 2 | 3, "CAS and fixture directory, optionally one actual DEB");
   MC_Runtime.Initialize (Status); Need ("runtime");
   if MC_Posix.Euid = 0 then
      CT.Stage (Store, Envelope, Counter'Last, Result, Status);
      Expect (Status = Denied and then Result = CT.Inventory'(others => <>), "root control reader refused");
      Report; return;
   end if;
   MC_Clock.Boottime_Milliseconds (Now, Status); Need ("clock"); Deadline := Now + 120_000;
   MC_Store.Initialize (Ada.Command_Line.Argument (1), Store, Status); Need ("fresh private CAS");
   MC_FS.Open_Root (Ada.Directories.Full_Name (Ada.Command_Line.Argument (2)), Media, Status); Need ("fixture directory");
   if Ada.Command_Line.Argument_Count = 3 then
      Inspect (Ada.Command_Line.Argument (3)); Need ("actual control archive");
      Ada.Text_IO.Put_Line ("ORIGINAL " & MC_Hex.Encode (Result.Original));
      Ada.Text_IO.Put_Line ("ARCHIVE " & MC_Hex.Encode (Result.Archive));
      for I in 1 .. Result.Count loop
         declare Item : CT.Control_Entry renames Result.Entries (I); begin
            Ada.Text_IO.Put_Line ("ENTRY " & MC_Text.Image (Item.Name) & " " & CT.Entry_Kind'Image (Item.Kind)
               & " " & MC_Hex.Encode (Item.Content) & Counter'Image (Item.Size) & Word'Image (Item.Mode)
               & Word'Image (Item.UID) & Word'Image (Item.GID) & Interfaces.Integer_64'Image (Item.Modified_Seconds));
         end;
      end loop;
   else
      Run ("valid-plain", True); Run ("valid-gzip", True); Run ("valid-xz", True);
      Run ("valid-zstd", True); Run ("valid-gnu", True);
      CT.Stage (Store, Envelope, Deadline, Result, Status); Need ("repeat immutable CAS staging");
      Expect (Result = Saved, "repeat inventory identical");
      CT.Stage (Store, Envelope, 0, Result, Status);
      Expect (Status = Stale and then Result.Count = 0, "expired control staging");
      Envelope.Items (Envelope.Control_Index).Offset := Envelope.Items (Envelope.Control_Index).Offset + 1;
      CT.Stage (Store, Envelope, Deadline, Result, Status);
      Expect (Status = Conflict and then Result.Count = 0, "forged control envelope refused before decoding");
      Inspect ("count-boundary.deb"); Need ("entry count boundary");
      Expect (Result.Count = CT.Max_Entries, "exactly 64 entries accepted");
      Run ("missing-control", False); Run ("duplicate", False); Run ("traversal", False);
      Run ("absolute", False); Run ("nested", False); Run ("space", False);
      Run ("symlink", False); Run ("hardlink", False); Run ("device", False); Run ("fifo", False);
      Run ("directory-file", False); Run ("bad-checksum", False); Run ("truncated-content", False);
      Run ("wrong-codec", False); Run ("truncated-xz", False); Run ("too-many", False);
      Run ("pax-attributes", False); Run ("bad-gzip-crc", False); Run ("truncated-zstd", False);
      Run ("expanded-limit", False); Run ("total-limit", False); Run ("nested-compression", False);
      Run ("trailing-gzip", False); Run ("trailing-xz", False); Run ("trailing-zstd", False);
      Run ("concatenated-gzip", False); Run ("concatenated-xz", False); Run ("concatenated-zstd", False);
      Run ("tar-padding-limit", False);
   end if;
   MC_FS.Close (Media); MC_Store.Close (Store); Report;
exception when others => MC_FS.Close (Media); MC_Store.Close (Store); raise;
end Run_Deb_Control_Tests;
