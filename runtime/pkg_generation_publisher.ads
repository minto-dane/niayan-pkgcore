-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with Pkg_Managed_Engine; with Pkg_Generation_Descriptor;
with Pkg_Selected_Catalog; with Pkg_Payload_Index;
generic
   with package Managed is new Pkg_Managed_Engine (<>);
   with procedure Authorize_Stage
     (Manifest, Plan, Evidence : Digest; Stage_ID, Transaction_ID : Identity;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome);
   with procedure Authorize_Bootstrap (Root_ID : Identity; Grant : Digest; Status : out Outcome);
package Pkg_Generation_Publisher with SPARK_Mode => Off is
   procedure Provision (Root_Path, State_Path : String; Root_ID : Identity;
      Bootstrap_Grant : Digest; Status : out Outcome);
   procedure Publish (Root_Path, State_Path, Store_Path, Generation_Bank : String;
      Expected_Plan, Health_Receipt : Digest; Deadline : Counter; Status : out Outcome);
   procedure Read_Current (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Current : out Pkg_Generation_Descriptor.Descriptor; Status : out Outcome);
   procedure Read_Current_Catalog (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Deadline : Counter; Current : out Pkg_Generation_Descriptor.Descriptor;
      Value : in out Pkg_Selected_Catalog.Catalog; Payload : in out Pkg_Payload_Index.Index;
      Status : out Outcome);
   -- Publish and Read_Current_Catalog require a v2 manifest with its exact CAS
   -- retention closure. Structural v1 remains readable only as metadata. Publish
   -- requires a finite deadline and checks it in the composed execution guard.
   -- Reobserves the accepted native catalog and payload while holding the same
   -- publication/root reservations used for descriptor and journal validation.
   -- Every failure clears descriptor, catalog and payload together. CAS readers
   -- check the pinned closure BEFORE catalog reconstruction, so missing derived
   -- objects fail. No accepted publication state is altered by these readers.
   -- Locks are released on return: this is a consistent planning observation,
   -- NOT a lease or update grant. Publish still compares the exact predecessor
   -- under its own reservation; metadata-only Read_Current is not native proof.
   -- Internal, unprivileged publication SDK. Every effect goes through the full
   -- managed guard; no default authority, external effects, or boot switch.
   -- Generation bank layout is fixed: <stage-id hex>/root and <stage-id hex>/state.
   -- The verified stage reservation stays held through publication/reconciliation.
   -- Only root.state's accepted plan selects a generation. generation.next is
   -- unpublished workspace; consumers MUST NOT read it as the current pointer.
   -- Read_Current verifies accepted metadata and journal, not physical root/boot
   -- health or an execution grant. An active transaction returns Indeterminate.
   -- Missing publication state/locks are never re-created during recovery.
   -- Bootstrap, live adapters, trust floors and target boot remain site obligations.
end Pkg_Generation_Publisher;
