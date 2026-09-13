-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with Pkg_Deb_Final_Set; with Pkg_Generation_Descriptor;
with Pkg_Site_Supply; with Pkg_Supply_Planner;
package Pkg_Update_Planner with SPARK_Mode => Off is
   type Preparation is record
      Before : Pkg_Generation_Descriptor.Descriptor := Pkg_Generation_Descriptor.Empty;
      Root_ID, Transaction_ID : Identity := Zero_Identity;
      Before_Closure, Catalog, Closure, Intent, Transition_Binding : Digest := Zero_Digest;
      Supply_Map, Retained_Policy, Policy_Hash, Floor_Hash : Digest := Zero_Digest;
      Observed_UTC, Valid_Until, Deadline : Counter := 0;
   end record;
   procedure Prepare (Root_Path, State_Path, Store_Path, Policy_Path, Floor_Path : String;
      Root_ID, Transaction_ID : Identity; Expected_Current, Catalog, Closure : Digest;
      Native_Architecture : String; Enabled : Pkg_Deb_Final_Set.Architecture_List;
      Items : Pkg_Supply_Planner.Requests; Observer_UID : Word; Deadline : Counter;
      Site : in out Pkg_Site_Supply.Session; Result : out Preparation; Status : out Outcome);
   -- Concrete ordinary-update preparation against the actual accepted catalog.
   -- One current publication/root/store reservation spans the predecessor and
   -- retention audit, native DEB transition, retained intent, real archive
   -- observer and exact target-minus-predecessor supply map. Final accepted
   -- state, current site inputs and original deadline are reobserved.
   -- Expected_Current comes from the selected predecessor observation. An active
   -- or initial root never becomes an invented empty predecessor. A change to
   -- the predecessor is refused; the caller must plan a new explicit request.
   -- Result is cleared and Site closed on every failure. Immutable CAS objects
   -- and external trust checkpoints can already exist; no automatic retry/GC.
   -- On success Site remains in planning mode with its original pins and UTC.
   -- The physical planner must bind the actual final plan with Bind_Publication.
   -- This does not select the target package set, compile full DEB effects or a
   -- root image, grant execution, publish a generation or activate a boot entry.
   -- All current managed/configuration/barrier/native-admission gates remain
   -- mandatory, including revalidation under the later execution reservation.
end Pkg_Update_Planner;
