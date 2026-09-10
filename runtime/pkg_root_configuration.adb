-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Containers.Indefinite_Ordered_Maps; with Ada.Containers.Vectors;
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Codec; with MC_Posix;
with Pkg_Root_Archive; with Pkg_Payload_Index; with Pkg_Selected_Catalog;
with Pkg_Catalog_Store; with Pkg_Deb_Conffiles;
package body Pkg_Root_Configuration with SPARK_Mode => Off is
   package C renames Pkg_Conffile_Choice; package P renames Pkg_Deb_Payload;
   package X renames Pkg_Payload_Index; package A renames Pkg_Root_Archive;
   package D renames Pkg_Deb_Conffiles;
   use type Proposal_Access; use type Interfaces.C.unsigned; use type P.Entry_Kind; use type C.Attribute_Source;
   type Node is record Claim, Effect : Natural := 0; end record;
   package Paths is new Ada.Containers.Indefinite_Ordered_Maps (String, Node);
   package Positions is new Ada.Containers.Vectors (Positive, Paths.Cursor, Paths."=");
   type Configured_Entry is record
      Effect : C.File_Effect;
      Decision, Closure : Digest := Zero_Digest;
   end record;
   package Effects is new Ada.Containers.Vectors (Positive, Configured_Entry);
   package Bindings is new Ada.Containers.Vectors (Positive, Choice_Binding);
   type Data is record
      Inputs : Input_Binding;
      Names : Paths.Map;
      Order : Positions.Vector;
      Configured : Effects.Vector;
      Choices : Bindings.Vector;
   end record;
   procedure Free is new Ada.Unchecked_Deallocation (Data, Data_Access);
   procedure Clear (Value : in out Layout) is
   begin Free (Value.State); end Clear;
   overriding procedure Finalize (Value : in out Layout) is
   begin Clear (Value); end Finalize;
   function Count (Value : Layout) return Natural is
     (if Value.State = null then 0 else Natural (Value.State.Order.Length));
   function Binding (Value : Layout) return Input_Binding is
     (if Value.State = null then (others => <>) else Value.State.Inputs);
   function Choice_Count (Value : Layout) return Natural is
     (if Value.State = null then 0 else Natural (Value.State.Choices.Length));
   procedure Read_Choice (Value : Layout; Position : Positive; Item : out Choice_Binding; Status : out Outcome) is
   begin
      Item := (others => <>); Status := Invalid_Input;
      if Position > Choice_Count (Value) then return; end if;
      Item := Value.State.Choices.Element (Position); Status := OK;
   end Read_Choice;
   procedure Read_Entry (Value : Layout; Position : Positive; Item : out Entry_Reference; Status : out Outcome) is
   begin
      Item := (others => <>); Status := Invalid_Input;
      if Position > Count (Value) then return; end if;
      declare Cursor : constant Paths.Cursor := Value.State.Order.Element (Position);
         Selected : constant Node := Paths.Element (Cursor);
      begin
         Item.Path := P.Byte_Strings.To_Bounded_String (Paths.Key (Cursor)); Item.Base_Claim := Selected.Claim;
         if Selected.Effect /= 0 then
            declare Configured : constant Configured_Entry := Value.State.Configured.Element (Selected.Effect); begin
               Item.Configuration := Configured.Effect; Item.Decision := Configured.Decision;
               Item.Retained_Closure := Configured.Closure;
            end;
         end if;
      end;
      Status := OK;
   end Read_Entry;
   procedure Prepare (Store : in out MC_Store.Store; Manifest, Catalog, Closure : Digest;
      Root_ID, Transaction : Identity; Context : Digest; Native_Architecture : String;
      Selected : Choices; Limit, Deadline : Counter; Value : in out Layout; Status : out Outcome) is
      type Buffer_Access is access Bytes;
      procedure Free is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
      package Scope_Maps is new Ada.Containers.Indefinite_Ordered_Maps (String, C.Scope, "=" => C."=");
      Scopes : Scope_Maps.Map; Reserved : Paths.Map;
      Wire : Buffer_Access := null; Used : Natural;
      Base : Pkg_Selected_Catalog.Catalog; Payload : X.Index;
      Source : X.Package_Source; Declarations : D.Inventory; Declaration : D.Declaration;
      Archive, Owned : Digest; Now : Counter; Names_Size : Counter := 0;
      Interrupted : exception;
      procedure Need is
      begin if Status /= OK then raise Interrupted; end if; end Need;
      procedure Clock is
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status); Need;
         if Deadline = Counter'Last or else Now >= Deadline then Status := Stale; raise Interrupted; end if;
      end Clock;
      procedure Refuse (Reason : Outcome := Conflict) is
      begin Status := Reason; raise Interrupted; end Refuse;
      procedure Name_Budget (Name : String) is
      begin
         if Counter (Name'Length) > Counter (X.Max_Name_Bytes) - Names_Size then Refuse (Exhausted); end if;
         Names_Size := Names_Size + Counter (Name'Length);
      end Name_Budget;
      function Relative (Name : P.Byte_Strings.Bounded_String) return String is
         Text : constant String := P.Byte_Strings.To_String (Name);
      begin
         if Text'Length < 2 or else Text (Text'First) /= '/' then Refuse (Corrupt); end if;
         return Text (Text'First + 1 .. Text'Last);
      end Relative;
      function Has_Source (Original : Digest) return Boolean is
         First : Positive := 1; Last : Positive := X.Package_Count (Payload) + 1; Middle : Positive;
         Item : X.Package_Source;
      begin
         while First < Last loop
            Clock; Middle := First + (Last - First) / 2; X.Read_Package (Payload, Middle, Item, Status); Need;
            if Item.Original < Original then First := Middle + 1; else Last := Middle; end if;
         end loop;
         if First > X.Package_Count (Payload) then return False; end if;
         X.Read_Package (Payload, First, Item, Status); Need; return Item.Original = Original;
      end Has_Source;
      function Is_Directory (Name : String) return Boolean is
         Item : X.Claim; Cursor : constant Paths.Cursor := Value.State.Names.Find (Name);
      begin
         if not Paths.Has_Element (Cursor) or else Paths.Element (Cursor).Effect /= 0 then return False; end if;
         X.Read_Claim (Payload, Paths.Element (Cursor).Claim, Item, Status); Need;
         return Item.Item.Values.Kind = P.Directory;
      end Is_Directory;
      procedure Apply (Effect : C.File_Effect; Binding : C.Scope; Backup : Boolean;
         Decision, Retained_Closure : Digest) is
         Name : constant String := Relative (Effect.Path); Cursor : Paths.Cursor;
         Item : X.Claim;
      begin
         Clock;
         if Reserved.Contains (Name) then Refuse; end if;
         Name_Budget (Name); Reserved.Insert (Name, (others => <>));
         Cursor := Value.State.Names.Find (Name);
         if Paths.Has_Element (Cursor) then
            if Backup or else Paths.Element (Cursor).Effect /= 0 then Refuse; end if;
            X.Read_Claim (Payload, Paths.Element (Cursor).Claim, Item, Status); Need;
            if Item.Item.Values.Kind /= P.Regular or else Binding.Incoming_Original = Zero_Digest
               or else Item.Source.Original /= Binding.Incoming_Original then Refuse; end if;
            Value.State.Names.Delete (Cursor);
         end if;
         if Effect.Source /= C.No_File then
            Value.State.Configured.Append (Configured_Entry'(Effect, Decision, Retained_Closure));
            Value.State.Names.Insert (Name, (0, Natural (Value.State.Configured.Length)));
         end if;
      end Apply;
   begin
      Clear (Value); Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Root_ID = Zero_Identity or else Transaction = Zero_Identity or else Context = Zero_Digest
         or else Native_Architecture'Length = 0 or else Selected'Length > Max_Choices then return; end if;
      Clock;
      A.Verify_Ownership (Store, Manifest, Catalog, Closure, Native_Architecture, Limit, Deadline, Archive, Owned, Status); Need;
      Pkg_Catalog_Store.Load (Store, Catalog, Deadline, Base, Payload, Status); Need;
      Wire := new Bytes (1 .. A.Header_Size + 8 * X.Path_Count (Payload));
      MC_Store.Read_Object (Store, Manifest, Wire.all, Used, Status); Need;
      if Used /= Wire'Length then Refuse (Corrupt); end if;
      Value.State := new Data;
      Value.State.Inputs := (Manifest, Catalog, Closure, Archive, Owned, Root_ID, Transaction, Context);
      for I in 1 .. X.Path_Count (Payload) loop
         Clock;
         declare Claim : constant Positive := Positive (MC_Codec.U64 (Wire.all, A.Header_Size + 8 * (I - 1) + 1));
            Item : X.Claim;
         begin
            X.Read_Claim (Payload, Claim, Item, Status); Need;
            declare Name : constant String := P.Byte_Strings.To_String (Item.Item.Path); begin
               Name_Budget (Name); Value.State.Names.Insert (Name, (Claim, 0));
            end;
         end;
      end loop;
      Free (Wire);
      for Reference of Selected loop
         Clock; if Reference.Value = null then Refuse (Invalid_Input); end if;
         declare Binding : C.Scope; Target, Backup : C.File_Effect; begin
            C.Read_Scope (Store, Reference.Value.all, Reference.Decision, Reference.Closure, Deadline, Binding, Status); Need;
            if Binding.Root_ID /= Root_ID or else Binding.Transaction /= Transaction or else Binding.Context /= Context then Refuse; end if;
            if Binding.Incoming_Original /= Zero_Digest and then not Has_Source (Binding.Incoming_Original) then Refuse; end if;
            C.Read_Effects (Store, Reference.Value.all, Reference.Decision, Reference.Closure, Deadline, Target, Backup, Status); Need;
            Value.State.Choices.Append (Choice_Binding'(Target.Path, C.Address (Reference.Value.all), Reference.Decision, Reference.Closure));
            declare Name : constant String := Relative (Target.Path); begin
               if Scopes.Contains (Name) then Refuse; end if;
               Scopes.Insert (Name, Binding);
            end;
            Apply (Target, Binding, False, Reference.Decision, Reference.Closure);
            if P.Byte_Strings.Length (Backup.Path) /= 0 then
               Apply (Backup, Binding, True, Reference.Decision, Reference.Closure);
            end if;
         end;
      end loop;
      -- Cover declarations from all selected originals, including removals and
      -- missing payload declarations. A plain vendor root is not configuration.
      for I in 1 .. X.Package_Count (Payload) loop
         Clock; X.Read_Package (Payload, I, Source, Status); Need;
         D.Inspect (Store, Source.Original, Deadline, Declarations, Status); Need;
         for J in 1 .. D.Count (Declarations) loop
            Clock; D.Read_Entry (Declarations, J, Declaration, Status); Need;
            declare Name : constant String := Relative (Declaration.Path); begin
               if not Scopes.Contains (Name) or else Scopes.Element (Name).Incoming_Original /= Source.Original then Refuse; end if;
            end;
         end loop;
      end loop;
      if not Is_Directory ("") then Refuse; end if;
      for Cursor in Value.State.Names.Iterate loop
         Clock;
         declare Name : constant String := Paths.Key (Cursor); Item : X.Claim; begin
            for I in Name'Range loop
               if Name (I) = '/' and then not Is_Directory (Name (Name'First .. I - 1)) then Refuse; end if;
            end loop;
            if Paths.Element (Cursor).Claim /= 0 then
               X.Read_Claim (Payload, Paths.Element (Cursor).Claim, Item, Status); Need;
               if Item.Item.Values.Kind = P.Hard_Link then
                  declare Target : constant String := P.Byte_Strings.To_String (Item.Item.Link_Target); begin
                     if Reserved.Contains (Target) then Refuse (Unsupported); end if;
                  end;
               end if;
            end if;
            Value.State.Order.Append (Cursor);
         end;
      end loop;
      -- All choices must still be live after the whole catalog/namespace pass.
      for Reference of Selected loop
         C.Recheck (Store, Reference.Value.all, Reference.Decision, Reference.Closure, Deadline, Status); Need;
      end loop;
      Clock; Status := OK;
   exception
      when Interrupted => Free (Wire); Clear (Value);
      when Storage_Error => Free (Wire); Clear (Value); Status := Exhausted;
      when others => Free (Wire); Clear (Value); Status := Indeterminate;
   end Prepare;
end Pkg_Root_Configuration;
