-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Finalization; with Interfaces.C;
with MC_Types; use MC_Types;
with Pkg_Generation_Stage; with Pkg_Root_Handoff; with Pkg_Root_Identity;
generic
   with procedure Authorize_Stage
     (Manifest, Plan, Evidence : Digest; Stage_ID, Transaction_ID : Identity;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome);
   with procedure Observe_Configuration
     (Generation : Digest; Root_ID, Transaction_ID : Identity;
      Context : Digest; Phase : String; Root_FD : out Integer; Status : out Outcome);
   with procedure Observe_Root
     (Generation : Digest; Stage_ID : Identity; Phase : String;
      Original_Deadline : out Counter; Root : out Pkg_Root_Identity.Root_Identity;
      Status : out Outcome);
   with procedure Check_Lifetime
     (Generation : Digest; Stage_ID : Identity; Deadline : Counter;
      Phase : String; Status : out Outcome);
package Pkg_Generation_Execution with SPARK_Mode => Off is
   type Execution is new Ada.Finalization.Limited_Controlled with private;
   procedure Start
     (C : in out Execution; Root_Path, State_Path, Store_Path : String;
      Encoded_Manifest : Bytes; Expected_Manifest, Expected_Worker : Digest;
      Prepare_Channel, Reinspect_Channel : Integer; Deadline : Counter;
      Status : out Outcome);
   procedure Check (C : in out Execution; Status : out Outcome);
   function Held (C : Execution) return Boolean;
   function Observation (C : Execution) return Pkg_Root_Identity.Root_Identity;
   function Completed_Batches (C : Execution) return Natural;
   procedure Close (C : in out Execution);
   overriding procedure Finalize (C : in out Execution);
   -- One nonroot execution: fresh native provisioning, bounded batch staging,
   -- real prepare handoff, independent root observation and reinspection while
   -- holding generation/root/CAS reservations. No shell, public CLI or root UID.
   -- All four providers are mandatory. Check_Lifetime maintains the SAME current
   -- supervisor/operator/supply/consent context and external physical exclusion;
   -- it must not translate a transport ACK or polkit result into those facts.
   -- Providers retain authority until AFTER Close. Observe_Root is independent
   -- of the controller reply. Configuration has no unavailable/allow default.
   -- Start accepts only physical v5/v6 manifests and one original <=120s
   -- BOOTTIME deadline. Both private channels are opened before any staging
   -- mutation, and no delivery, batch or uncertain operation is retried.
   -- Any failure after provisioning was attempted is Indeterminate. Durable
   -- intent/content/journals remain; Close never repairs, unpins or deletes them.
   -- An Execution cannot be restarted, including after Close or failure. The
   -- existing durable first-use barriers also remain mandatory across processes.
   -- Held/Observation are local live-handle checks, not fresh authorization.
   -- Check additionally invokes the current lifetime and independent root
   -- providers. A failure invalidates observation but retains reservations until
   -- Close, so caller can arrange controller shutdown before releasing authority.
   -- This prepares an INACTIVE physical root; it does not publish the catalog,
   -- run unmodeled DEB effects, select a boot entry or attest successful recovery.
   -- One owning process/task; no parallel Start/Check/Close or external reaper.
private
   package Staging is new Pkg_Generation_Stage (Authorize_Stage, Observe_Configuration);
   type Phase is (New_Execution, Binding, Provisioning, Advancing, Preparing,
                  Reinspecting, Holding, Failed, Closed);
   type Execution is new Ada.Finalization.Limited_Controlled with record
      Current : Phase := New_Execution;
      Owner : Interfaces.C.int := 0;
      Generation, Worker : Digest := Zero_Digest;
      Stage : Identity := Zero_Identity;
      Deadline : Counter := 0;
      Completed : Natural := 0;
      Mutation_Attempted : Boolean := False;
      Preparation, Reinspection : Pkg_Root_Handoff.Session;
      Physical : Staging.Reinspected_Generation;
   end record;
end Pkg_Generation_Execution;
