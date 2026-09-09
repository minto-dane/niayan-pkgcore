-- SPDX-License-Identifier: MIT
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_Posix;
with Pkg_Deb_Payload;
package body Pkg_Catalog_Store with SPARK_Mode => Off is
   package C renames Pkg_Selected_Catalog; package X renames Pkg_Payload_Index;
   package P renames Pkg_Deb_Payload;
   use type Interfaces.C.unsigned; use type Byte; use type Wide;
   Tag : constant String := "NIACSEL1";
   type Buffer_Access is access Bytes;
   procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
   procedure Time_Left (Deadline : Counter; Status : out Outcome) is
      Now : Counter;
   begin
      MC_Clock.Boottime_Milliseconds (Now, Status);
      if Status = OK and then Now >= Deadline then Status := Stale; end if;
   end Time_Left;
   procedure Save (Store : in out MC_Store.Store; Value : C.Catalog;
                   Deadline : Counter; Address : out Digest; Status : out Outcome) is
      W : MC_Store.Writer; Header : Bytes (1 .. Header_Size) := (others => 0);
      Entry_Data : Bytes (1 .. Entry_Size); Item : C.Package_Record;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Tick is
      begin Time_Left (Deadline, Status); Check; end Tick;
   begin
      Address := Zero_Digest; Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Tick;
      if not C.Sealed (Value) then Status := Invalid_Input; return; end if;
      MC_Codec.Put64 (Header, 1, Tag'Length);
      for I in Tag'Range loop Header (8 + I) := Byte (Character'Pos (Tag (I))); end loop;
      Header (17 .. 48) := C.Payload_Hash (Value); MC_Codec.Put64 (Header, 49, Wide (C.Package_Count (Value)));
      MC_Store.Begin_Write (Store, C.Fingerprint (Value), Counter (Header_Size + Entry_Size * C.Package_Count (Value)), W, Status); Check;
      Tick; MC_Store.Write_Chunk (W, Header, Status); Check;
      for I in 1 .. C.Package_Count (Value) loop
         Tick; C.Read_Package (Value, I, Item, Status); Check;
         Entry_Data (1 .. 32) := Item.Original; Entry_Data (33 .. 64) := Item.Archive; Entry_Data (65 .. 96) := Item.Control;
         MC_Store.Write_Chunk (W, Entry_Data, Status); Check;
      end loop;
      Tick; MC_Store.Finish_Write (Store, W, Status); Check; Tick;
      Address := C.Fingerprint (Value); Status := OK;
   exception
      when Interrupted => MC_Store.Abort_Write (W); Address := Zero_Digest;
      when Storage_Error => MC_Store.Abort_Write (W); Address := Zero_Digest; Status := Exhausted;
      when others => MC_Store.Abort_Write (W); Address := Zero_Digest; Status := Indeterminate;
   end Save;
   procedure Load (Store : in out MC_Store.Store; Address : Digest; Deadline : Counter;
                   Value : in out C.Catalog; Payload : in out X.Index; Status : out Outcome) is
      Buffer : Buffer_Access := null; Used, Count : Natural;
      Source : P.Inventory; Previous, Original, Expected_Payload : Digest := Zero_Digest;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Tick is
      begin Time_Left (Deadline, Status); Check; end Tick;
      procedure Fail is
      begin C.Clear (Value); X.Clear (Payload); P.Clear (Source); Free (Buffer); end Fail;
   begin
      C.Clear (Value); X.Clear (Payload); Status := Denied;
      if MC_Posix.Euid = 0 then return; end if;
      Tick;
      if Address = Zero_Digest then Status := Invalid_Input; return; end if;
      Buffer := new Bytes (1 .. Max_Bytes);
      MC_Store.Read_Object (Store, Address, Buffer.all, Used, Status); Check; Tick;
      Status := Corrupt;
      if Used < Header_Size or else MC_Codec.U64 (Buffer.all, 1) /= Tag'Length then raise Interrupted; end if;
      for I in Tag'Range loop
         if Buffer (8 + I) /= Byte (Character'Pos (Tag (I))) then Status := Unsupported; raise Interrupted; end if;
      end loop;
      if MC_Codec.U64 (Buffer.all, 49) > Wide (C.Max_Packages) then Status := Exhausted; raise Interrupted; end if;
      Count := Natural (MC_Codec.U64 (Buffer.all, 49)); Expected_Payload := Buffer (17 .. 48);
      if Count = 0 or else Used /= Header_Size + Entry_Size * Count or else Expected_Payload = Zero_Digest then raise Interrupted; end if;
      -- Validate all framing and source order before observing any package.
      for I in 1 .. Count loop
         declare Offset : constant Positive := Header_Size + Entry_Size * (I - 1) + 1; begin
            Original := Buffer (Offset .. Offset + 31);
            if Original <= Previous or else Buffer (Offset + 32 .. Offset + 63) = Zero_Digest
              or else Buffer (Offset + 64 .. Offset + 95) = Zero_Digest then raise Interrupted; end if;
            Previous := Original;
         end;
      end loop;
      declare Selected : C.Selection (1 .. Count); begin
         for I in 1 .. Count loop
            declare Offset : constant Positive := Header_Size + Entry_Size * (I - 1) + 1; begin
               Tick; Selected (I).Original := Buffer (Offset .. Offset + 31);
               Selected (I).Control := Buffer (Offset + 64 .. Offset + 95);
               P.Stage (Store, Selected (I).Original, Deadline, Source, Status); Check;
               X.Add (Payload, Source, Deadline, Status); Check; P.Clear (Source);
               C.Add (Value, Store, Selected (I).Original, Deadline, Status); Check;
            end;
         end loop;
         X.Seal (Payload, Deadline, Status); Check;
         if X.Fingerprint (Payload) /= Expected_Payload then Status := Corrupt; raise Interrupted; end if;
         C.Seal (Value, Selected, Payload, Deadline, Status); Check;
      end;
      -- This also checks the original compressed-control digests in the frame.
      if C.Fingerprint (Value) /= Address then Status := Corrupt; raise Interrupted; end if;
      Tick; Free (Buffer); Status := OK;
   exception
      when Interrupted => Fail;
      when Storage_Error => Fail; Status := Exhausted;
      when others => Fail; Status := Indeterminate;
   end Load;
end Pkg_Catalog_Store;
