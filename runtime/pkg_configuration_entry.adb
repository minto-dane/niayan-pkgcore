-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Strings.Unbounded; with Ada.Strings.Fixed; with Ada.Unchecked_Deallocation;
with Interfaces.C; with Interfaces.C.Strings; with System;
with MC_Clock; with MC_Codec; with MC_FS; with MC_Posix;
with Pkg_Conffile_Observation; with Pkg_Conffile_Transition; with Pkg_Deb_Payload;
with Pkg_Tar_Output;
package body Pkg_Configuration_Entry with SPARK_Mode => Off is
   package C renames Pkg_Conffile_Choice; package O renames Pkg_Conffile_Observation;
   package P renames Pkg_Deb_Payload; package T renames Pkg_Tar_Output;
   use Ada.Strings.Unbounded; use Interfaces.C; use Interfaces.C.Strings;
   use type System.Address; use type C.Attribute_Source; use type P.Entry_Kind;
   use type Pkg_Conffile_Transition.File_Kind; use type Word; use type Wide; use type Byte;
   function New_Entry return System.Address with Import, Convention => C, External_Name => "archive_entry_new";
   procedure Free_Entry (E : System.Address) with Import, Convention => C, External_Name => "archive_entry_free";
   procedure Set_Flags (E : System.Address; Set, Clear : unsigned_long)
      with Import, Convention => C, External_Name => "archive_entry_set_fflags";
   procedure Get_Flags (E : System.Address; Set, Clear : access unsigned_long)
      with Import, Convention => C, External_Name => "archive_entry_fflags";
   function Flag_Text (E : System.Address) return chars_ptr
      with Import, Convention => C, External_Name => "archive_entry_fflags_text";
   function Copy_Flags (E : System.Address; Text : char_array) return chars_ptr
      with Import, Convention => C, External_Name => "archive_entry_copy_fflags_text";
   function Strnlen (P : chars_ptr; N : size_t) return size_t
      with Import, Convention => C, External_Name => "strnlen";
   type Buffer_Access is access Bytes;
   procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
   function Raw (Text : String) return Bytes is
      Result : Bytes (1 .. Text'Length);
   begin
      for I in Result'Range loop Result (I) := Character'Pos (Text (Text'First + I - 1)); end loop;
      return Result;
   end Raw;
   function Decimal (ID : Word) return String is
     (Ada.Strings.Fixed.Trim (Word'Image (ID), Ada.Strings.Both));
   procedure Prepare (Store : in out MC_Store.Store; Effect : C.File_Effect;
      Deadline : Counter; Prefix : out Digest; Size : out Counter; Status : out Outcome) is
      Header : T.Header; Payload : P.Inventory; Item : P.Payload_Entry; Local, Override : O.Observation;
      Values : P.Attributes; Buffer : Bytes (1 .. MC_FS.Max_Xattr_Bytes); Used : Natural;
      Output : Buffer_Access := null; Saved : Digest; Override_Mode : Boolean := False;
      E, Check_E : System.Address := System.Null_Address;
      Interrupted : exception;
      procedure Need is
      begin if Status /= OK then raise Interrupted; end if; end Need;
      procedure Refuse (Reason : Outcome := Corrupt) is
      begin Status := Reason; raise Interrupted; end Refuse;
      procedure Tick is
         Now : Counter;
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status); Need;
         if Deadline = Counter'Last or else Now >= Deadline then Refuse (Stale); end if;
      end Tick;
      procedure Cleanup is
      begin
         Free (Output);
         if E /= System.Null_Address then Free_Entry (E); E := System.Null_Address; end if;
         if Check_E /= System.Null_Address then Free_Entry (Check_E); Check_E := System.Null_Address; end if;
      end Cleanup;
      function Relative (Name : P.Byte_Strings.Bounded_String) return String is
         Text : constant String := P.Byte_Strings.To_String (Name);
      begin
         if Text'Length < 2 or else Text (Text'First) /= '/' then Refuse (Invalid_Input); end if;
         return Text (Text'First + 1 .. Text'Last);
      end Relative;
      procedure Permissions (Mode, UID, GID : Word) is
      begin
         if Effect.Mode /= (Mode and 8#7777#) or else Effect.UID /= UID or else Effect.GID /= GID then Refuse (Conflict); end if;
      end Permissions;
      procedure Check_Local (Value : O.Observation) is
      begin
         if O.Image (Value).Kind /= Pkg_Conffile_Transition.Regular then Refuse (Conflict); end if;
         if O.Attributes (Value).Links /= 1 then Refuse (Unsupported); end if;
      end Check_Local;
      procedure Access_ACL (Data : Bytes; Native : Boolean) is
         type ACL_Entry is record Tag, ID : Word := 0; Perm : Natural := 0; end record;
         Entries : array (1 .. 1_024) of ACL_Entry;
         Count, Pos : Natural := 0;
         Owner, Group, Mask, Other : Natural := 0; Named : Boolean := False;
         Text : Unbounded_String;
         function Number (At_Byte : Positive; Length : Positive) return Word is
            Result : Word := 0;
         begin
            if At_Byte < Data'First or else At_Byte > Data'Last or else Length > Data'Last - At_Byte + 1 then Refuse; end if;
            if Native then
               for I in reverse 0 .. Length - 1 loop Result := Result * 256 + Word (Data (At_Byte + I)); end loop;
            else
               for I in 0 .. Length - 1 loop Result := Result * 256 + Word (Data (At_Byte + I)); end loop;
            end if;
            return Result;
         end Number;
         function Label (Tag : Word) return String is
           (case Tag is when 1 | 2 => "user", when 4 | 8 => "group", when 16 => "mask", when others => "other");
         function Permission (Bits : Natural) return String is
           ((if Bits / 4 = 1 then "r" else "-") & (if Bits / 2 mod 2 = 1 then "w" else "-")
            & (if Bits mod 2 = 1 then "x" else "-"));
      begin
         if Native then
            if Data'Length < 4 or else Number (Data'First, 4) /= 2 or else (Data'Length - 4) mod 8 /= 0 then Refuse; end if;
            Count := (Data'Length - 4) / 8; Pos := Data'First + 4;
         else
            if Data'Length < 2 then Refuse; end if;
            Count := Natural (Number (Data'First, 2)); Pos := Data'First + 2;
            if Count = 0 then if Data'Length /= 2 then Refuse; end if; return; end if;
         end if;
         if Count not in 3 .. Entries'Length then Refuse (Unsupported); end if;
         for I in 1 .. Count loop
            Tick;
            if Native then
               Entries (I) := (Number (Pos, 2), Number (Pos + 4, 4), Natural (Number (Pos + 2, 2))); Pos := Pos + 8;
            else
               if Number (Pos, 4) /= 16#100# then Refuse (Unsupported); end if;
               declare Perm : constant Word := Number (Pos + 4, 4); begin
                  if Perm > 7 then Refuse; end if; Entries (I).Perm := Natural (Perm);
               end;
               Entries (I).Tag := (case Number (Pos + 8, 4) is when 10001 => 2, when 10002 => 1,
                  when 10003 => 8, when 10004 => 4, when 10005 => 16, when 10006 => 32, when others => 0);
               Entries (I).ID := Number (Pos + 12, 4);
               declare Length : constant Natural := Natural (Number (Pos + 16, 2)); begin
                  Pos := Pos + 18;
                  if Length > Data'Last - Pos + 1 then Refuse; end if;
                  for J in 0 .. Length - 1 loop if Data (Pos + J) = 0 then Refuse; end if; end loop;
                  Pos := Pos + Length; -- Original symbolic labels remain in the retained source record.
               end;
            end if;
            if Entries (I).Perm > 7 then Refuse; end if;
            case Entries (I).Tag is
               when 1 => if Owner /= 0 then Refuse; end if; Owner := I;
               when 4 => if Group /= 0 then Refuse; end if; Group := I;
               when 16 => if Mask /= 0 then Refuse; end if; Mask := I;
               when 32 => if Other /= 0 then Refuse; end if; Other := I;
               when 2 | 8 =>
                  Named := True; if Entries (I).ID = Word'Last then Refuse; end if;
                  -- The platform ACL text reader saturates larger IDs at INT_MAX.
                  if Entries (I).ID > Word (Interfaces.C.int'Last) then Refuse (Unsupported); end if;
               when others => Refuse (Unsupported);
            end case;
            if Entries (I).Tag not in 2 | 8 and then Entries (I).ID /= Word'Last then Refuse; end if;
            for J in 1 .. I - 1 loop
               if Entries (J).Tag = Entries (I).Tag and then Entries (J).ID = Entries (I).ID then Refuse; end if;
            end loop;
         end loop;
         if Pos /= Data'Last + 1 or else Owner = 0 or else Group = 0 or else Other = 0 or else (Named and then Mask = 0) then Refuse; end if;
         declare Group_Class : constant Positive := (if Mask = 0 then Group else Mask); begin
            if Entries (Owner).Perm /= Natural (Values.Mode / 64 mod 8)
               or else Entries (Group_Class).Perm /= Natural (Values.Mode / 8 mod 8)
               or else Entries (Other).Perm /= Natural (Values.Mode mod 8) then Refuse; end if;
            if Override_Mode then
               Entries (Owner).Perm := Natural (Effect.Mode / 64 mod 8);
               Entries (Group_Class).Perm := Natural (Effect.Mode / 8 mod 8);
               Entries (Other).Perm := Natural (Effect.Mode mod 8);
            end if;
         end;
         -- Canonical tag/ID order, using numeric identities without NSS lookup.
         for I in 1 .. Count loop
            for J in I + 1 .. Count loop
               if Entries (J).Tag < Entries (I).Tag or else
                 (Entries (J).Tag = Entries (I).Tag and then Entries (J).ID < Entries (I).ID)
               then declare Swap : constant ACL_Entry := Entries (I); begin Entries (I) := Entries (J); Entries (J) := Swap; end; end if;
            end loop;
            if I /= 1 then Append (Text, ","); end if;
            Append (Text, Label (Entries (I).Tag) & ":" &
               (if Entries (I).Tag in 2 | 8 then Decimal (Entries (I).ID) else "") & ":" & Permission (Entries (I).Perm));
         end loop;
         T.Add_Extension (Header, "SCHILY.acl.access", Raw (To_String (Text)), Status); Need;
      end Access_ACL;
      procedure Xattr (Name : String; Data : Bytes; Native : Boolean) is
      begin
         if Name = "system.posix_acl_access" then
            if not Native then Refuse (Unsupported); end if;
            Access_ACL (Data, True);
         elsif Name = "system.posix_acl_default" then Refuse (Unsupported);
         else T.Add_Xattr (Header, Name, Data, Status); Need;
         end if;
      end Xattr;
      function Local_Flag_Mask return Wide is
         Result : Wide := 0; Bit : Wide; Text : chars_ptr; Length : size_t;
         Got_Set, Got_Clear : aliased unsigned_long;
      begin
         E := New_Entry; Check_E := New_Entry;
         if E = System.Null_Address or else Check_E = System.Null_Address then Refuse (Exhausted); end if;
         for Position in 0 .. 31 loop
            Tick; Bit := Wide'(2) ** Position;
            Set_Flags (E, unsigned_long (Bit), 0); Text := Flag_Text (E);
            if Text /= Null_Ptr then
               Length := Strnlen (Text, 4_097);
               if Length in 1 .. 4_096 then
                  Set_Flags (Check_E, 0, 0);
                  if Copy_Flags (Check_E, To_C (Interfaces.C.Strings.Value (Text, Length))) = Null_Ptr then
                     Get_Flags (Check_E, Got_Set'Access, Got_Clear'Access);
                     if Wide (Got_Set) = Bit and then Got_Clear = 0 then Result := Result or Bit; end if;
                  end if;
               end if;
            end if;
         end loop;
         Free_Entry (E); E := System.Null_Address; Free_Entry (Check_E); Check_E := System.Null_Address;
         return Result and not Wide'(16#80000#); -- Extent layout is not a behavioural flag.
      end Local_Flag_Mask;
      procedure Flags (Set, Clear : Wide) is
         Text : chars_ptr; Length : size_t; Got_Set, Got_Clear : aliased unsigned_long;
      begin
         if (Set and Clear) /= 0 or else Set > Wide (unsigned_long'Last) or else Clear > Wide (unsigned_long'Last) then Refuse (Unsupported); end if;
         if Set = 0 and then Clear = 0 then return; end if;
         E := New_Entry; Check_E := New_Entry;
         if E = System.Null_Address or else Check_E = System.Null_Address then Refuse (Exhausted); end if;
         Set_Flags (E, unsigned_long (Set), unsigned_long (Clear)); Text := Flag_Text (E);
         if Text = Null_Ptr then Refuse (Unsupported); end if;
         Length := Strnlen (Text, 4_097); if Length = 0 or else Length > 4_096 then Refuse (Unsupported); end if;
         declare Image : constant String := Interfaces.C.Strings.Value (Text, Length); begin
            if Copy_Flags (Check_E, To_C (Image)) /= Null_Ptr then Refuse (Unsupported); end if;
            Get_Flags (Check_E, Got_Set'Access, Got_Clear'Access);
            if Wide (Got_Set) /= Set or else Wide (Got_Clear) /= Clear then Refuse (Unsupported); end if;
            T.Add_Extension (Header, "SCHILY.fflags", Raw (Image), Status); Need;
         end;
         Free_Entry (E); E := System.Null_Address; Free_Entry (Check_E); Check_E := System.Null_Address;
      end Flags;
   begin
      Prefix := Zero_Digest; Size := 0; Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Effect.Source = C.No_File or else Effect.Object = Zero_Digest or else Effect.Content = Zero_Digest
         or else MC_Store.Native_Reservation (Store) < 0 or else Effect.Mode > 8#7777# then return; end if;
      Tick;
      if Effect.Source = C.Local_Observation then
         if Effect.Permission_Override /= Zero_Digest then Refuse (Invalid_Input); end if;
         O.Load (Store, Effect.Object, P.Byte_Strings.To_String (Effect.Source_Path), Deadline, Local, Status); Need; Check_Local (Local);
         declare Attr : constant O.File_Attributes := O.Attributes (Local); begin
            Permissions (Attr.Node.Mode, Attr.Node.UID, Attr.Node.GID);
            Values.Mode := Attr.Node.Mode and 8#7777#; Values.UID := Attr.Node.UID; Values.GID := Attr.Node.GID;
            Values.Content := O.Image (Local).Content; Values.Content_Size := Attr.Size;
            Values.Modified := Attr.Modified; Values.Accessed := Attr.Accessed;
            Values.Changed := Attr.Changed; Values.Created := Attr.Created;
            -- FS_EXTENT_FL describes storage layout, not a requested mutation.
            -- Other active unrecognized effects require a separate platform plan.
            if (Attr.Attributes and not Wide'(16#74#)) /= 0 then Refuse (Unsupported); end if;
            if (Attr.Attributes and Wide'(16#74#)) /= (Attr.Inode_Flags and Attr.Attribute_Mask and Wide'(16#74#)) then Refuse; end if;
            Values.Flags_Set := Attr.Inode_Flags and not Wide'(16#80000#);
            -- Explicitly clear supported behavioural flags absent from the source.
            -- No encryption/verity/layout state is manufactured from plaintext.
            Values.Flags_Clear := Local_Flag_Mask and not Values.Flags_Set;
         end;
      else
         P.Stage (Store, Effect.Object, Deadline, Payload, Status); Need;
         declare Position : constant Natural := P.Find (Payload, Relative (Effect.Source_Path)); begin
            if Position = 0 then Refuse (Conflict); end if;
            P.Read_Entry (Payload, Position, Item, Status); Need;
         end;
         if Item.Values.Kind /= P.Regular then Refuse (Unsupported); end if;
         Values := Item.Values;
         if Effect.Permission_Override /= Zero_Digest then
            O.Load (Store, Effect.Permission_Override, P.Byte_Strings.To_String (Effect.Source_Path), Deadline, Override, Status);
            Need; Check_Local (Override); Override_Mode := True;
            declare Attr : constant O.File_Attributes := O.Attributes (Override); begin
               Permissions (Attr.Node.Mode, Attr.Node.UID, Attr.Node.GID);
            end;
         else Permissions (Values.Mode, Values.UID, Values.GID);
         end if;
      end if;
      if Values.Content /= Effect.Content then Refuse (Conflict); end if;
      T.Start (Header, Relative (Effect.Path), Effect.Mode, Effect.UID, Effect.GID, Values.Content_Size,
         (Values.Modified, Values.Accessed, Values.Changed, Values.Created), Status); Need;
      if Effect.Source = C.Local_Observation then
         for I in 1 .. O.Xattr_Count (Local) loop
            Tick;
            declare Name : P.Byte_Strings.Bounded_String; begin
               O.Read_Xattr (Local, I, Name, Buffer, Used, Status); Need;
               Xattr (P.Byte_Strings.To_String (Name), Buffer (1 .. Used), True);
            end;
         end loop;
      else
         MC_Store.Read_Object (Store, Values.Xattrs, Buffer, Used, Status); Need;
         if Used < 2 then Refuse; end if;
         declare Pos : Natural := 3; Last : P.Byte_Strings.Bounded_String; begin
            for I in 1 .. MC_Codec.U16 (Buffer, 1) loop
               Tick; if Pos > Used or else Used - Pos + 1 < 6 then Refuse; end if;
               declare Length : constant Natural := MC_Codec.U16 (Buffer, Pos);
                  N : constant Word := MC_Codec.U32 (Buffer, Pos + 2);
               begin
                  Pos := Pos + 6;
                  if Length not in 1 .. 255 or else N > 65_536 or else Length + Natural (N) > Used - Pos + 1 then Refuse; end if;
                  declare Name : String (1 .. Length); begin
                     for J in Name'Range loop Name (J) := Character'Val (Buffer (Pos + J - 1)); end loop;
                     if (for some Ch of Name => Ch = ASCII.NUL) or else Name <= P.Byte_Strings.To_String (Last) then Refuse; end if;
                     Last := P.Byte_Strings.To_Bounded_String (Name); Pos := Pos + Length;
                     Xattr (Name, Buffer (Pos .. Pos + Natural (N) - 1), False); Pos := Pos + Natural (N);
                  end;
               end;
            end loop;
            if Pos /= Used + 1 then Refuse; end if;
         end;
         MC_Store.Read_Object (Store, Values.ACLs, Buffer, Used, Status); Need; Access_ACL (Buffer (1 .. Used), False);
      end if;
      Flags (Values.Flags_Set, Values.Flags_Clear); Tick;
      Output := new Bytes (1 .. T.Max_Header); T.Finish (Header, Output.all, Used, Status); Need;
      MC_Store.Put (Store, Output (1 .. Used), Saved, Status); Need; Tick;
      Prefix := Saved; Size := Values.Content_Size; Cleanup;
   exception
      when Interrupted => Cleanup; Prefix := Zero_Digest; Size := 0;
      when Storage_Error => Cleanup; Prefix := Zero_Digest; Size := 0; Status := Exhausted;
      when others => Cleanup; Prefix := Zero_Digest; Size := 0; Status := Indeterminate;
   end Prepare;
end Pkg_Configuration_Entry;
