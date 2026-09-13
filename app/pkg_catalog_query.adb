-- SPDX-License-Identifier: BSD-3-Clause
-- Private concrete accepted-catalog query, never a publication executor.
with Ada.Command_Line; with Interfaces.C;
with MC_Types; use MC_Types;
with MC_Runtime; with MC_Posix; with MC_Clock; with MC_Codec; with MC_Hex; with MC_Text;
with Pkg_Generation_Reader; with Pkg_Generation_Descriptor;
with Pkg_Selected_Catalog; with Pkg_Payload_Index;
procedure Pkg_Catalog_Query with SPARK_Mode => Off is
   use Ada.Command_Line;
   use type Interfaces.C.int; use type Interfaces.C.long; use type Interfaces.C.unsigned;
   Value : Pkg_Selected_Catalog.Catalog;
   Payload : Pkg_Payload_Index.Index;
   Current : Pkg_Generation_Descriptor.Descriptor;
   Item : Pkg_Selected_Catalog.Package_Record;
   Root_ID : Identity := Zero_Identity;
   Deadline, Started, Finished : Counter := 0;
   Status : Outcome := Invalid_Input;
   Header : Bytes (1 .. 224) := (others => 0);
   Prefix : Bytes (1 .. 48) := (others => 0);
   procedure Emit (Data : Bytes) is
      B : aliased Bytes (1 .. Data'Length) := Data;
      Offset : Natural := 0;
      Written : Interfaces.C.long;
      Now : Counter;
   begin
      for Attempt in 1 .. 12_000 loop
         exit when Offset = B'Length;
         MC_Clock.Boottime_Milliseconds (Now, Status);
         if Status /= OK or else Now >= Deadline then raise Program_Error; end if;
         Written := MC_Posix.Write (1, B (Offset + 1)'Address,
            Interfaces.C.size_t (B'Length - Offset));
         if Written = -1 and then MC_Posix.Errno_Location.all = MC_Posix.EAGAIN then delay 0.01;
         elsif Written <= 0 or else Written > Interfaces.C.long (B'Length - Offset) then raise Program_Error;
         else Offset := Offset + Natural (Written); end if;
      end loop;
      if Offset /= B'Length then raise Program_Error; end if;
   end Emit;
   procedure Emit_Text (Text : MC_Text.Value) is
      S : constant String := MC_Text.Image (Text);
      B : Bytes (1 .. 2 + S'Length) := (others => 0);
   begin
      MC_Codec.Put16 (B, 1, S'Length);
      for I in S'Range loop B (I + 2) := Character'Pos (S (I)); end loop;
      Emit (B);
   end Emit_Text;
   procedure Close is
   begin Pkg_Selected_Catalog.Clear (Value); Pkg_Payload_Index.Clear (Payload); end Close;
begin
   if Argument_Count /= 5 then Set_Exit_Status (64); return; end if;
   MC_Runtime.Initialize (Status);
   if Status = OK then MC_Hex.Decode (Argument (4), Root_ID, Status); end if;
   Deadline := Counter'Value (Argument (5));
   if Status = OK then MC_Clock.Boottime_Milliseconds (Started, Status); end if;
   if Status /= OK or else Root_ID = Zero_Identity or else Deadline >= Counter'Last
     or else Deadline <= Started or else Deadline - Started > 120_000 then
      Set_Exit_Status (2); return;
   end if;
   declare Flags : constant Interfaces.C.int := MC_Posix.Dup (1, 3, 0); begin
      if Flags < 0 or else MC_Posix.Dup (1, 4, Interfaces.C.int
         (Interfaces.C.unsigned (Flags) or Interfaces.C.unsigned (MC_Posix.O_NONBLOCK))) /= 0
      then raise Program_Error; end if;
   end;
   Pkg_Generation_Reader.Read_Current_Catalog (Argument (1), Argument (2), Argument (3),
      Root_ID, Deadline, Current, Value, Payload, Status);
   if Status /= OK then Close; Set_Exit_Status (2); return; end if;
   MC_Clock.Boottime_Milliseconds (Finished, Status);
   if Status /= OK or else Finished < Started or else Finished >= Deadline then
      Close; Set_Exit_Status (2); return;
   end if;
   Header (1 .. 8) := (78, 73, 65, 81, 82, 89, 48, 49); -- NIAQRY01
   Header (9 .. 200) := Pkg_Generation_Descriptor.Encode (Current);
   MC_Codec.Put64 (Header, 201, Wide (Started)); MC_Codec.Put64 (Header, 209, Wide (Finished));
   MC_Codec.Put64 (Header, 217, Wide (Pkg_Selected_Catalog.Package_Count (Value)));
   Emit (Header);
   for I in 1 .. Pkg_Selected_Catalog.Package_Count (Value) loop
      Pkg_Selected_Catalog.Read_Package (Value, I, Item, Status);
      if Status /= OK then raise Program_Error; end if;
      Prefix := (others => 0); Prefix (1 .. 32) := Item.Original;
      if Item.Identity.Has_Installed_Size then
         MC_Codec.Put64 (Prefix, 33, Wide (Item.Identity.Installed_Size_KiB));
      end if;
      Prefix (41) := Boolean'Pos (Item.Identity.Essential);
      Prefix (42) := Boolean'Pos (Item.Identity.Protected_Package);
      Prefix (43) := Boolean'Pos (Item.Identity.Has_Installed_Size);
      Emit (Prefix);
      Emit_Text (Item.Identity.Name); Emit_Text (Item.Identity.Version); Emit_Text (Item.Identity.Architecture);
   end loop;
   Close;
   Set_Exit_Status (0); -- The parent additionally requires complete framing and EOF.
exception when others => Close; Set_Exit_Status (2);
end Pkg_Catalog_Query;
