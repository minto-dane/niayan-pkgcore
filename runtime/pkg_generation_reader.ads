-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with Pkg_Generation_Descriptor; with Pkg_Selected_Catalog; with Pkg_Payload_Index;
with Pkg_Deb_Final_Set; with Pkg_Deb_Transition;
with MC_Store; with Pkg_Generation_Manifest;
package Pkg_Generation_Reader with SPARK_Mode => Off is
   procedure Read_Current (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Current : out Pkg_Generation_Descriptor.Descriptor; Status : out Outcome);
   procedure Read_Current_Catalog (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Deadline : Counter; Current : out Pkg_Generation_Descriptor.Descriptor;
      Value : in out Pkg_Selected_Catalog.Catalog; Payload : in out Pkg_Payload_Index.Index;
      Status : out Outcome);
   procedure Read_Current_Transition
     (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Expected_Current, Target_Catalog, Target_Closure : Digest;
      Native_Architecture : String; Enabled : Pkg_Deb_Final_Set.Architecture_List;
      Deadline : Counter; Current : out Pkg_Generation_Descriptor.Descriptor;
      Result : in out Pkg_Deb_Transition.Plan; Binding : out Digest;
      Issue : out Pkg_Deb_Transition.Finding; Status : out Outcome);
   generic
      with procedure Process (Store : in out MC_Store.Store;
         Current : Pkg_Generation_Descriptor.Descriptor;
         Image : Pkg_Generation_Manifest.Manifest; Status : out Outcome);
   procedure With_Current (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Deadline : Counter; Status : out Outcome);
   -- Run candidate preparation while the exact accepted root/publication/store
   -- reservations are held. Retention is verified before Process; accepted state
   -- and deadline are checked again after it. No physical root FD or effect
   -- permission is passed. Process may retain immutable candidate CAS data only;
   -- it must not reacquire the store or publish accepted state. Its owner clears
   -- all successful outputs on any final failure of With_Current.
   -- Concrete native accepted-state reader, with no write-authority callbacks.
   -- Takes the same existing publication/root/store reservations as the writer;
   -- verifies root marker, accepted descriptor and complete terminal journal.
   -- Catalog/transition reads verify retained closure before loading originals,
   -- then reobserve accepted state and deadline before exposing any output.
   -- No state, lock or missing retention is bootstrapped or repaired. A busy,
   -- active, uninitialized or incomplete root is never an empty installed set.
   -- Catalog decoding can populate immutable derived CAS objects; it never
   -- changes an accepted package catalog. Outputs are consistent observations,
   -- not retained leases, current boot attestation or update permission.
   -- A planner must revalidate the exact predecessor under its own reservation.
   -- The caller must bound process lifetime/resources for synchronous native IO.
end Pkg_Generation_Reader;
