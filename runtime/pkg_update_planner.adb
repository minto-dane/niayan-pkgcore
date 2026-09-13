-- SPDX-License-Identifier: BSD-3-Clause
with Interfaces.C; with MC_Clock; with MC_Posix; with MC_SHA256; with MC_Store;
with Pkg_Generation_Reader; with Pkg_Generation_Manifest; with Pkg_Generation_Intent;
with Pkg_Supply_Map;
package body Pkg_Update_Planner with SPARK_Mode => Off is
   use type Interfaces.C.unsigned;
   procedure Prepare (Root_Path, State_Path, Store_Path, Policy_Path, Floor_Path : String;
      Root_ID, Transaction_ID : Identity; Expected_Current, Catalog, Closure : Digest;
      Native_Architecture : String; Enabled : Pkg_Deb_Final_Set.Architecture_List;
      Items : Pkg_Supply_Planner.Requests; Observer_UID : Word; Deadline : Counter;
      Site : in out Pkg_Site_Supply.Session; Result : out Preparation; Status : out Outcome) is
      Candidate : Preparation;
      Started, Now : Counter;
      procedure Plan (Store : in out MC_Store.Store;
         Current : Pkg_Generation_Descriptor.Descriptor;
         Image : Pkg_Generation_Manifest.Manifest; Status : out Outcome) is
         Target : Pkg_Supply_Map.Context;
      begin
         Status := Stale;
         if MC_SHA256.Hash (Pkg_Generation_Descriptor.Encode (Current)) /= Expected_Current then return; end if;
         Candidate.Before := Current; Candidate.Before_Closure := Image.Catalog_Closure;
         Target := (Root_ID, Current, Image.Catalog_Closure, Catalog, Closure);
         Pkg_Generation_Intent.Prepare (Store, Root_ID, Current, Image.Catalog_Closure,
            Catalog, Closure, Native_Architecture, Enabled, Deadline,
            Candidate.Intent, Candidate.Transition_Binding, Status);
         if Status /= OK then return; end if;
         Pkg_Supply_Planner.Prepare (Store, Site, Transaction_ID, Target, Items,
            Observer_UID, Deadline, Candidate.Supply_Map, Candidate.Retained_Policy,
            Candidate.Valid_Until, Status);
         if Status /= OK then return; end if;
         Pkg_Site_Supply.Observe_Inputs (Site, Candidate.Policy_Hash, Candidate.Floor_Hash,
            Candidate.Observed_UTC, Status);
         if Status = OK and then Candidate.Valid_Until /= 0
           and then Candidate.Observed_UTC >= Candidate.Valid_Until then Status := Stale; end if;
      end Plan;
      procedure On_Current is new Pkg_Generation_Reader.With_Current (Plan);
   begin
      Result := (others => <>); Status := Denied;
      if MC_Posix.Euid = 0 or else Observer_UID = 0 then Pkg_Site_Supply.Close (Site); return; end if;
      Status := Invalid_Input;
      if Root_ID = Zero_Identity or else Transaction_ID = Zero_Identity or else Expected_Current = Zero_Digest
        or else Catalog = Zero_Digest or else Closure = Zero_Digest or else Deadline in 0 | Counter'Last then
         Pkg_Site_Supply.Close (Site); return; end if;
      MC_Clock.Boottime_Milliseconds (Started, Status);
      if Status /= OK then Pkg_Site_Supply.Close (Site); return; end if;
      if Deadline <= Started or else Deadline - Started > 120_000 then Status := Stale; Pkg_Site_Supply.Close (Site); return; end if;
      Pkg_Site_Supply.Open_Planning (Policy_Path, Floor_Path, Root_ID, Transaction_ID,
         Deadline, Site, Status);
      if Status = OK then
         Candidate.Root_ID := Root_ID; Candidate.Transaction_ID := Transaction_ID;
         Candidate.Catalog := Catalog; Candidate.Closure := Closure; Candidate.Deadline := Deadline;
         On_Current (Root_Path, State_Path, Store_Path, Root_ID, Deadline, Status);
      end if;
      if Status = OK then
         Pkg_Site_Supply.Observe_Inputs (Site, Candidate.Policy_Hash, Candidate.Floor_Hash,
            Candidate.Observed_UTC, Status);
      end if;
      if Status = OK then MC_Clock.Boottime_Milliseconds (Now, Status); end if;
      if Status = OK and then (Now < Started or else Now >= Deadline
        or else (Candidate.Valid_Until /= 0 and then Candidate.Observed_UTC >= Candidate.Valid_Until)) then Status := Stale; end if;
      if Status = OK then Result := Candidate; else Pkg_Site_Supply.Close (Site); end if;
   exception when others =>
      Result := (others => <>); Pkg_Site_Supply.Close (Site); Status := Indeterminate;
   end Prepare;
end Pkg_Update_Planner;
