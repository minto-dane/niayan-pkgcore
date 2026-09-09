-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
with Pkg_Managed_Engine; with Pkg_Generation_Descriptor;
with Pkg_Selected_Catalog; with Pkg_Payload_Index;
with Pkg_Deb_Final_Set; with Pkg_Deb_Transition;
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
   procedure Read_Current_Transition
     (Root_Path, State_Path, Store_Path : String; Root_ID : Identity;
      Expected_Current, Target_Catalog, Target_Closure : Digest;
      Native_Architecture : String; Enabled : Pkg_Deb_Final_Set.Architecture_List;
      Deadline : Counter; Current : out Pkg_Generation_Descriptor.Descriptor;
      Result : in out Pkg_Deb_Transition.Plan; Binding : out Digest;
      Issue : out Pkg_Deb_Transition.Finding; Status : out Outcome);
   -- Checks an ordinary update against the exact expected accepted descriptor,
   -- retaining publication/root/CAS locks through both native catalog loads,
   -- retention verification, endpoint/protection checks and final reobservation.
   -- Binding hashes NIAUPD01 + descriptor hash + target catalog + target closure
   -- + transition fingerprint. All four fields are 32-byte digests. The native
   -- transition also binds the complete explicit architecture policy.
   -- Failure clears Current, Result and Binding, retaining only a native finding
   -- when the transition checker reports one. An uninitialized/active generation
   -- cannot be used as an empty baseline. Missing retained data is not rebuilt.
   -- This is planning evidence, not supply authentication, a phase schedule or
   -- execution permission. Locks are released on return. Admission must validate
   -- policy, effects and this exact predecessor under its own live reservation.
   -- Publish requires a v3 manifest carrying a retained native intent. The intent
   -- is bound through manifest/descriptor to the physical plan checked by the
   -- existing managed authority. Native dependencies, protection and the exact
   -- predecessor are revalidated from originals before any publication effect.
   -- Initial construction requires the actual initial root state and a checked
   -- native endpoint; an ordinary intent cannot bypass baseline protections.
   -- Native reads accept retained v2/v3; v1 remains metadata-only. Publish rejects
   -- v1/v2 plans, including their replay: legacy recovery needs its retained
   -- implementation before migration. There is no policy-free fallback path.
   -- Publish requires a finite deadline and checks it in the composed guard.
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
