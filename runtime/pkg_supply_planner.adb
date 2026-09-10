-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Unchecked_Deallocation; with Interfaces.C;
with MC_Clock; with MC_Posix;
with Pkg_Archive_Observer; with Pkg_Supply_Policy;
package body Pkg_Supply_Planner with SPARK_Mode => Off is
   use type Word; use type Interfaces.C.unsigned;
   type Sources_Access is access Pkg_Supply_Map.Sources;
   procedure Free is new Ada.Unchecked_Deallocation (Pkg_Supply_Map.Sources, Sources_Access);
   procedure Prepare (Store : in out MC_Store.Store; Site : in out Pkg_Site_Supply.Session;
      Transaction_ID : Identity; Target : Pkg_Supply_Map.Context; Items : Requests;
      Observer_UID : Word; Deadline : Counter;
      Map, Retained_Policy : out Digest; Valid_Until : out Counter; Status : out Outcome) is
      Current : Pkg_Supply_Policy.Snapshot;
      Sources : Sources_Access := null;
      Held : constant Integer := MC_Store.Native_Reservation (Store);
      Boot, Request_Deadline, Until_Time : Counter;
      Receipt, Policy, Saved_Map, Saved_Policy : Digest := Zero_Digest;
      Selected : Natural;
      Interrupted : exception;
      procedure Check is
      begin if Status /= OK then raise Interrupted; end if; end Check;
      procedure Observe is
      begin
         if MC_Store.Native_Reservation (Store) /= Held then Status := Conflict; raise Interrupted; end if;
         MC_Clock.Boottime_Milliseconds (Boot, Status); Check;
         if Boot >= Deadline then Status := Stale; raise Interrupted; end if;
         Pkg_Site_Supply.Observe_Planning (Site, Target.Root_ID, Transaction_ID, Current, Status); Check;
         MC_Clock.Boottime_Milliseconds (Boot, Status); Check;
         if Boot >= Deadline then Status := Stale; raise Interrupted; end if;
      end Observe;
   begin
      Map := Zero_Digest; Retained_Policy := Zero_Digest; Valid_Until := 0; Status := Denied;
      if MC_Posix.Euid = 0 then raise Interrupted; end if;
      Status := Invalid_Input;
      if Held < 0 or else Transaction_ID = Zero_Identity or else Target.Root_ID = Zero_Identity
        or else Deadline in 0 | Counter'Last or else Items'Length > Pkg_Supply_Map.Max_Entries
        or else Observer_UID = 0 or else Observer_UID = Word (MC_Posix.Euid) then raise Interrupted; end if;
      for I in Items'Range loop
         declare R : Request renames Items (I); begin
            if R.Request_ID = Zero_Digest or else R.Scope = Zero_Digest or else R.Original = Zero_Digest
              or else R.Control = Zero_Digest or else R.InRelease = Zero_Digest or else R.Index = Zero_Digest
              or else R.Keyring = Zero_Digest or else MC_Text.Length (R.Index_Path) = 0
              or else MC_Text.Length (R.Deb_Path) = 0
              or else (I > Items'First and then Items (I - 1).Original >= R.Original) then raise Interrupted; end if;
         end;
      end loop;
      Observe;
      Sources := new Pkg_Supply_Map.Sources (1 .. Items'Length);
      for I in Items'Range loop
         Observe; Selected := 0;
         for J in 1 .. Current.Count loop
            if Current.Trusted (J).Scope = Items (I).Scope then Selected := J; exit; end if;
         end loop;
         if Selected = 0 then Status := Denied; raise Interrupted; end if;
         Request_Deadline := (if Deadline - Boot > 125_000 then Boot + 125_000 else Deadline);
         Pkg_Archive_Observer.Observe (Store, Items (I).Request_ID, Items (I).Original, Items (I).Control,
            Items (I).InRelease, Items (I).Index, Items (I).Keyring,
            MC_Text.Image (Items (I).Index_Path), MC_Text.Image (Items (I).Deb_Path), Observer_UID,
            Current.Trusted (Selected), Request_Deadline, Receipt, Policy, Status); Check;
         Sources (I - Items'First + 1) := (Items (I).Original, Items (I).Control, Receipt);
      end loop;
      Observe;
      Pkg_Supply_Map.Prepare (Store, Target, Sources.all, Current.Trusted (1 .. Current.Count),
         Current.Observed_At, Deadline, Saved_Map, Until_Time, Status); Check;
      Observe;
      Pkg_Supply_Policy.Prepare (Store, Saved_Map, Target, Current.Trusted (1 .. Current.Count),
         Current.Observed_At, Deadline, Saved_Policy, Until_Time, Status); Check;
      Observe;
      Pkg_Supply_Policy.Verify_New (Store, Saved_Policy, Target, Current.Trusted (1 .. Current.Count),
         Current.Observed_At, Deadline, Until_Time, Status); Check;
      -- Reobserve trust after the complete native verification. Expiry is
      -- exclusive; do not extend it to cover time spent in the final observation.
      Observe;
      if Until_Time /= 0 and then Current.Observed_At >= Until_Time then Status := Stale; raise Interrupted; end if;
      Map := Saved_Map; Retained_Policy := Saved_Policy; Valid_Until := Until_Time; Free (Sources);
   exception
      when Interrupted =>
         Free (Sources); Pkg_Site_Supply.Close (Site); Map := Zero_Digest; Retained_Policy := Zero_Digest; Valid_Until := 0;
      when Storage_Error =>
         Free (Sources); Pkg_Site_Supply.Close (Site); Map := Zero_Digest; Retained_Policy := Zero_Digest; Valid_Until := 0; Status := Exhausted;
      when others =>
         Free (Sources); Pkg_Site_Supply.Close (Site); Map := Zero_Digest; Retained_Policy := Zero_Digest; Valid_Until := 0; Status := Indeterminate;
   end Prepare;
end Pkg_Supply_Planner;
