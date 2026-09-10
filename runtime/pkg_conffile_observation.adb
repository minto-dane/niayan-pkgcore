-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Containers.Vectors; with Ada.Unchecked_Deallocation; with Interfaces; with Interfaces.C;
with MC_Clock; with MC_FS; with MC_Posix;
package body Pkg_Conffile_Observation with SPARK_Mode => Off is
   package P renames Pkg_Deb_Payload; package T renames Pkg_Conffile_Transition;
   use type Wide; use type Word; use type Interfaces.Integer_64; use type Interfaces.C.unsigned;
   type Buffer_Access is access Bytes;
   procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
   type Attribute_Span is record
      Name_First, Value_First : Positive;
      Name_Length, Value_Length : Natural;
   end record;
   package Spans is new Ada.Containers.Vectors (Positive, Attribute_Span);
   type Directories is array (1 .. 128) of Node_Identity;
   type Data is record
      Raw : Buffer_Access;
      Binding : Digest := Zero_Digest;
      Name : P.Byte_Strings.Bounded_String;
      Current : T.Image := (T.Other, Zero_Digest);
      Values : File_Attributes;
      UID, GID : Word := 0;
      Parents : Directories;
      Parent_Count, Missing_At : Natural := 0;
      Xattrs : Spans.Vector;
   end record;
   procedure Free is new Ada.Unchecked_Deallocation (Data, Data_Access);
   procedure Clear (Value : in out Observation) is
   begin if Value.State /= null then Free (Value.State.Raw); Free (Value.State); end if; end Clear;
   overriding procedure Finalize (Value : in out Observation) is
   begin Clear (Value); end Finalize;
   function Address (Value : Observation) return Digest is (if Value.State = null then Zero_Digest else Value.State.Binding);
   function Path (Value : Observation) return String is (if Value.State = null then "" else P.Byte_Strings.To_String (Value.State.Name));
   function Image (Value : Observation) return T.Image is (if Value.State = null then (T.Other, Zero_Digest) else Value.State.Current);
   function Attributes (Value : Observation) return File_Attributes is (if Value.State = null then (others => <>) else Value.State.Values);
   function Observer_UID (Value : Observation) return Word is (if Value.State = null then 0 else Value.State.UID);
   function Observer_GID (Value : Observation) return Word is (if Value.State = null then 0 else Value.State.GID);
   function Directory_Count (Value : Observation) return Natural is (if Value.State = null then 0 else Value.State.Parent_Count);
   function Missing_Component (Value : Observation) return Natural is (if Value.State = null then 0 else Value.State.Missing_At);
   function Xattr_Count (Value : Observation) return Natural is (if Value.State = null then 0 else Natural (Value.State.Xattrs.Length));
   procedure Read_Directory (Value : Observation; Position : Positive; Node : out Node_Identity; Status : out Outcome) is
   begin
      Node := (others => <>); Status := Invalid_Input;
      if Position > Directory_Count (Value) then return; end if;
      Node := Value.State.Parents (Position); Status := OK;
   end Read_Directory;
   procedure Read_Xattr (Value : Observation; Position : Positive;
      Name : out P.Byte_Strings.Bounded_String; Data : out Bytes; Used : out Natural; Status : out Outcome) is
   begin
      Name := P.Byte_Strings.Null_Bounded_String; Data := (others => 0); Used := 0; Status := Invalid_Input;
      if Position > Xattr_Count (Value) then return; end if;
      declare Span : constant Attribute_Span := Value.State.Xattrs (Position); Text : String (1 .. Span.Name_Length); begin
         if Span.Value_Length > Data'Length then Status := Exhausted; return; end if;
         for I in Text'Range loop Text (I) := Character'Val (Value.State.Raw (Span.Name_First + I - 1)); end loop;
         Data (Data'First .. Data'First + (Span.Value_Length - 1)) := Value.State.Raw (Span.Value_First .. Span.Value_First + (Span.Value_Length - 1));
         Name := P.Byte_Strings.To_Bounded_String (Text); Used := Span.Value_Length; Status := OK;
      end;
   end Read_Xattr;
   procedure Load (Store : MC_Store.Store; Address : Digest; Expected_Path : String;
      Deadline : Counter; Value : in out Observation; Status : out Outcome) is
      Buffer : Buffer_Access := null; Used, Pos : Natural := 0;
      Starts : array (1 .. 128) of Natural := (others => 0);
      Components, Names_Total, Attribute_Total : Natural := 0;
      Count, Tag, Number : Wide; File : MC_FS.File; Info : MC_FS.Entry_Info;
      Last_Name : P.Byte_Strings.Bounded_String;
      Interrupted : exception;
      procedure Need is
      begin if Status /= OK then raise Interrupted; end if; end Need;
      procedure Invalid is
      begin Status := Corrupt; raise Interrupted; end Invalid;
      procedure Tick is
         Now : Counter;
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status); Need;
         if Now >= Deadline or else Deadline = Counter'Last then Status := Stale; raise Interrupted; end if;
      end Tick;
      procedure Require (Size : Natural) is
      begin if Size > Used - Pos then Invalid; end if; end Require;
      function U64 return Wide is
         Result : Wide := 0;
      begin
         Require (8);
         for I in 0 .. 7 loop Result := Result or Interfaces.Shift_Left (Wide (Buffer (Pos + I + 1)), 8 * I); end loop;
         Pos := Pos + 8; return Result;
      end U64;
      function U32 return Word is
         Result : constant Wide := U64;
      begin if Result > Wide (Word'Last) then Invalid; end if; return Word (Result); end U32;
      function Text (Length : Natural) return String is
         Result : String (1 .. Length);
      begin
         Require (Length);
         for I in Result'Range loop Result (I) := Character'Val (Buffer (Pos + I)); end loop;
         Pos := Pos + Length; return Result;
      end Text;
      function Node return Node_Identity is
         Result : Node_Identity;
      begin
         Result.Mount := U64; Result.Device_Major := U32; Result.Device_Minor := U32; Result.Inode := U64;
         Result.Mode := U32; Result.UID := U32; Result.GID := U32;
         if Result.Mode > 16#FFFF# then Invalid; end if;
         return Result;
      end Node;
      function Clock return P.Timestamp is
         Seconds : constant Wide := U64; Nanos : constant Wide := U64; Result : P.Timestamp;
      begin
         if Nanos > 999_999_999 then Invalid; end if;
         Result.Present := True;
         Result.Seconds := (if Seconds <= Wide (Interfaces.Integer_64'Last) then Interfaces.Integer_64 (Seconds)
                            else -Interfaces.Integer_64 (not Seconds) - 1);
         Result.Nanoseconds := Natural (Nanos); return Result;
      end Clock;
      procedure Same_Mount (N : Node_Identity) is
         Root : constant Node_Identity := Value.State.Parents (1);
      begin
         if N.Mount /= Root.Mount or else N.Device_Major /= Root.Device_Major or else N.Device_Minor /= Root.Device_Minor then Invalid; end if;
      end Same_Mount;
   begin
      Clear (Value); Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Address = Zero_Digest or else Expected_Path'Length not in 2 .. P.Max_Name or else MC_Store.Native_Reservation (Store) < 0 then return; end if;
      Tick; Buffer := new Bytes (1 .. Max_Bytes); MC_Store.Read_Object (Store, Address, Buffer.all, Used, Status); Need;
      Require (8); if Buffer (1 .. 8) /= Bytes'(78,73,65,67,79,66,83,49) then Status := Unsupported; raise Interrupted; end if;
      Pos := 8; Number := U64; if Number not in 2 .. Wide (P.Max_Name) then Invalid; end if;
      Value.State := new Data;
      declare Name : constant String := Text (Natural (Number)); First : Positive := 2; begin
         if Name /= Expected_Path then Status := Conflict; raise Interrupted; end if;
         if Name (1) /= '/' or else (for some C of Name => C = ASCII.NUL) then Invalid; end if;
         for I in 2 .. Name'Last + 1 loop
            if I = Name'Last + 1 or else Name (I) = '/' then
               if I = First or else I - First > 255 or else Name (First .. I - 1) in "." | ".." or else Components = 128 then Invalid; end if;
               Components := Components + 1; Starts (Components) := First - 2; First := I + 1;
            end if;
         end loop;
         Value.State.Name := P.Byte_Strings.To_Bounded_String (Name);
      end;
      Value.State.UID := U32; Value.State.GID := U32;
      loop
         Tick; Tag := U64; exit when Tag /= 2;
         if Value.State.Parent_Count = Components then Invalid; end if;
         Value.State.Parent_Count := Value.State.Parent_Count + 1;
         declare N : constant Node_Identity := Node; begin
            if (N.Mode and 16#F000#) /= 16#4000# or else (N.Mode and 8#22#) /= 0
              or else (N.UID /= 0 and then N.UID /= Value.State.UID) then Invalid; end if;
            Value.State.Parents (Value.State.Parent_Count) := N; Same_Mount (N);
         end;
      end loop;
      if Value.State.Parent_Count = 0 then Invalid; end if;
      if Tag = 0 then
         Number := U64; if Number /= Wide (Starts (Value.State.Parent_Count)) then Invalid; end if;
         Value.State.Current := (T.Missing, Zero_Digest); Value.State.Missing_At := Value.State.Parent_Count;
      elsif Tag = 1 then
         if Value.State.Parent_Count /= Components then Invalid; end if;
         Value.State.Values.Node := Node; Same_Mount (Value.State.Values.Node);
         if (Value.State.Values.Node.Mode and 16#F000#) /= 16#8000# then Invalid; end if;
         Value.State.Values.Links := U32; if Value.State.Values.Links = 0 then Invalid; end if;
         Number := U64; if Number > Wide (MC_Store.Max_Object_Size) then Invalid; end if; Value.State.Values.Size := Counter (Number);
         Value.State.Values.Attributes := U64; Value.State.Values.Attribute_Mask := U64;
         if (Value.State.Values.Attributes and not Value.State.Values.Attribute_Mask) /= 0 then Invalid; end if;
         Value.State.Values.Accessed := Clock; Value.State.Values.Modified := Clock; Value.State.Values.Changed := Clock;
         Number := U64; if Number > 1 then Invalid; end if;
         if Number = 1 then Value.State.Values.Created := Clock; end if;
         Value.State.Values.Inode_Flags := U64;
         Count := U64; if Count > 32768 then Invalid; end if;
         for I in 1 .. Natural (Count) loop
            Tick;
            declare Span : Attribute_Span; begin
               Number := U64; if Number not in 1 .. 255 then Invalid; end if;
               Span.Name_First := Pos + 1; Span.Name_Length := Natural (Number);
               declare Name : constant String := Text (Span.Name_Length); begin
                  if (for some C of Name => C = ASCII.NUL) or else Name <= P.Byte_Strings.To_String (Last_Name) then Invalid; end if;
                  Last_Name := P.Byte_Strings.To_Bounded_String (Name);
               end;
               Number := U64; if Number > 65536 then Invalid; end if;
               Span.Value_First := Pos + 1; Span.Value_Length := Natural (Number); Require (Span.Value_Length); Pos := Pos + Span.Value_Length;
               Names_Total := Names_Total + Span.Name_Length + 1; Attribute_Total := Attribute_Total + Span.Name_Length + Span.Value_Length;
               if Names_Total > 65536 or else Attribute_Total > 131072 then Invalid; end if;
               Value.State.Xattrs.Append (Span);
            end;
         end loop;
         Value.State.Current.Kind := T.Regular;
      else Invalid;
      end if;
      Require (32); if Used - Pos /= 32 then Invalid; end if;
      if Tag = 0 then
         if Buffer (Pos + 1 .. Used) /= Zero_Digest then Invalid; end if;
      else
         Value.State.Current.Content := Buffer (Pos + 1 .. Used); if Value.State.Current.Content = Zero_Digest then Invalid; end if;
         Tick; MC_Store.Open_Object (Store, Value.State.Current.Content, File, Status); Need;
         MC_FS.Info (File, Info, Status); Need;
         if Info.Size /= Value.State.Values.Size then Invalid; end if;
         MC_FS.Close (File);
      end if;
      Tick; Value.State.Raw := new Bytes'(Buffer (1 .. Used)); Value.State.Binding := Address; Free (Buffer);
   exception
      when Interrupted => MC_FS.Close (File); Free (Buffer); Clear (Value);
      when Storage_Error => MC_FS.Close (File); Free (Buffer); Clear (Value); Status := Exhausted;
      when others => MC_FS.Close (File); Free (Buffer); Clear (Value); Status := Indeterminate;
   end Load;
end Pkg_Conffile_Observation;
