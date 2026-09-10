-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Containers.Vectors; with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Posix; with MC_Text;
with Pkg_Deb_Container; with Pkg_Deb_Control;
package body Pkg_Deb_Conffiles with SPARK_Mode => Off is
   use type Interfaces.C.unsigned; use type Pkg_Deb_Control.Entry_Kind; use type Byte;
   use type Pkg_Deb_Payload.Byte_Strings.Bounded_String;
   package Entries is new Ada.Containers.Vectors (Positive, Declaration);
   type Data is record
      Original, Raw : Digest := Zero_Digest;
      Items : Entries.Vector;
   end record;
   procedure Free is new Ada.Unchecked_Deallocation (Data, Data_Access);
   procedure Clear (Value : in out Inventory) is
   begin Free (Value.State); end Clear;
   overriding procedure Finalize (Value : in out Inventory) is
   begin Clear (Value); end Finalize;
   function Count (Value : Inventory) return Natural is
     (if Value.State = null then 0 else Natural (Value.State.Items.Length));
   function Original_Hash (Value : Inventory) return Digest is
     (if Value.State = null then Zero_Digest else Value.State.Original);
   function Declaration_Hash (Value : Inventory) return Digest is
     (if Value.State = null then Zero_Digest else Value.State.Raw);
   procedure Read_Entry (Value : Inventory; Position : Positive; Item : out Declaration; Status : out Outcome) is
   begin
      Item := (others => <>); Status := Invalid_Input;
      if Position > Count (Value) then return; end if;
      Item := Value.State.Items (Position); Status := OK;
   end Read_Entry;
   function Space (C : Character) return Boolean is (C in ASCII.HT | ASCII.VT | ASCII.FF | ASCII.CR | ' ');
   function Safe_Path (Name : String) return Boolean is
      First : Positive := Name'First + 1;
   begin
      if Name'Length not in 2 .. MC_Text.Max_Length or else Name (Name'First) /= '/' then return False; end if;
      for I in First .. Name'Last + 1 loop
         if I = Name'Last + 1 or else Name (I) = '/' then
            if I = First or else I - First > 255 or else Name (First .. I - 1) in "." | ".." then return False; end if;
            First := I + 1;
         elsif Name (I) = ASCII.NUL then return False;
         end if;
      end loop;
      return True;
   end Safe_Path;
   procedure Inspect (Store : in out MC_Store.Store; Original : Digest; Deadline : Counter;
      Value : in out Inventory; Status : out Outcome) is
      Envelope : Pkg_Deb_Container.Envelope;
      type Control_Access is access Pkg_Deb_Control.Inventory;
      type Bytes_Access is access Bytes;
      procedure Free is new Ada.Unchecked_Deallocation (Pkg_Deb_Control.Inventory, Control_Access);
      procedure Free is new Ada.Unchecked_Deallocation (Bytes, Bytes_Access);
      Control : Control_Access := null; Raw : Bytes_Access := null;
      Candidate : Data_Access := null;
      Payload : Pkg_Deb_Payload.Inventory;
      Now : Counter; Used, Conffiles : Natural := 0;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Tick is
      begin
         MC_Clock.Boottime_Milliseconds (Now, Status); Check;
         if Now >= Deadline then Status := Stale; raise Interrupted; end if;
      end Tick;
      procedure Line (Text : String) is
         First : Positive := Text'First; Last : Natural := Text'Last;
         Item : Declaration; Position : Natural;
         Flag : constant String := "remove-on-upgrade";
      begin
         Tick;
         while Last >= First and then Space (Text (Last)) loop Last := Last - 1; end loop;
         if Last < First then Status := Invalid_Input; raise Interrupted; end if;
         if Text (First) /= '/' then
            if Last - First + 1 <= Flag'Length or else Text (First .. First + Flag'Length - 1) /= Flag
              or else not Space (Text (First + Flag'Length)) then Status := Unsupported; raise Interrupted; end if;
            First := First + Flag'Length;
            while First <= Last and then Space (Text (First)) loop First := First + 1; end loop;
            Item.Remove_On_Upgrade := True;
         end if;
         if not Safe_Path (Text (First .. Last)) then Status := Invalid_Input; raise Interrupted; end if;
         Item.Path := Pkg_Deb_Payload.Byte_Strings.To_Bounded_String (Text (First .. Last));
         for Old of Candidate.Items loop
            if Old.Path = Item.Path then Status := Conflict; raise Interrupted; end if;
         end loop;
         if Natural (Candidate.Items.Length) >= Max_Entries then Status := Exhausted; raise Interrupted; end if;
         Position := Pkg_Deb_Payload.Find (Payload, Text (First + 1 .. Last));
         Item.Present := Position /= 0;
         if Item.Remove_On_Upgrade and then Item.Present then Status := Conflict; raise Interrupted; end if;
         if Item.Present then Pkg_Deb_Payload.Read_Entry (Payload, Position, Item.Payload, Status); Check; end if;
         Candidate.Items.Append (Item);
      end Line;
      procedure Cleanup is
      begin Free (Raw); Free (Control); Free (Candidate); end Cleanup;
   begin
      Clear (Value); Status := Denied; if MC_Posix.Euid = 0 then return; end if;
      Status := Invalid_Input;
      if Original = Zero_Digest or else Deadline in 0 | Counter'Last or else MC_Store.Native_Reservation (Store) < 0 then return; end if;
      Tick; Pkg_Deb_Container.Inspect (Store, Original, Deadline, Envelope, Status); Check;
      Control := new Pkg_Deb_Control.Inventory;
      Pkg_Deb_Control.Stage (Store, Envelope, Deadline, Control.all, Status); Check;
      Candidate := new Data; Candidate.Original := Original;
      for I in 1 .. Control.Count loop
         if MC_Text.Image (Control.Entries (I).Name) = "conffiles" then
            if Control.Entries (I).Kind /= Pkg_Deb_Control.Regular then Status := Invalid_Input; raise Interrupted; end if;
            Conffiles := I; exit;
         end if;
      end loop;
      if Conffiles /= 0 then
         Candidate.Raw := Control.Entries (Conffiles).Content;
         Raw := new Bytes (1 .. Natural (Control.Entries (Conffiles).Size));
         MC_Store.Read_Object (Store, Candidate.Raw, Raw.all, Used, Status); Check;
         if Used /= Raw'Length then Status := Corrupt; raise Interrupted; end if;
         Pkg_Deb_Payload.Stage (Store, Original, Deadline, Payload, Status); Check;
         declare
            Start : Positive := 1;
            procedure Read_Line (Last : Natural) is
            begin
               if Last - Start + 1 > 2 * MC_Text.Max_Length then Status := Exhausted; raise Interrupted; end if;
               declare Text : String (1 .. Last - Start + 1); begin
                  for J in Text'Range loop Text (J) := Character'Val (Raw (Start + J - 1)); end loop;
                  Line (Text);
               end;
            end Read_Line;
         begin
            for I in 1 .. Used loop
               if Raw (I) = 10 then Read_Line (I - 1); Start := I + 1; end if;
            end loop;
            if Start <= Used then Read_Line (Used); end if;
         end;
      end if;
      Tick; Value.State := Candidate; Candidate := null; Cleanup; Status := OK;
   exception
      when Interrupted => Cleanup; Clear (Value);
      when Storage_Error => Cleanup; Clear (Value); Status := Exhausted;
      when others => Cleanup; Clear (Value); Status := Indeterminate;
   end Inspect;
end Pkg_Deb_Conffiles;
