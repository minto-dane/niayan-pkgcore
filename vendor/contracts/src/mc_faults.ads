-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Faults with SPARK_Mode, Pure is
   type Domain is
     (Unknown_Domain, Software, Memory, CPU, Storage, Network, PCIe,
      Power, Thermal, Firmware, Security, Time_Service, Cluster_Control);
   type Severity is
     (Informational, Corrected, Degraded, Uncorrectable, Critical);
   type Persistence is (Transient, Intermittent, Persistent);
   type Evidence_Quality is
     (Untrusted, Authenticated_Observer, Corroborated, Attested_Source);
   type Disposition is
     (Observe, Degrade_Service, Drain_Node, Fence_Node, Reboot_Node,
      Repair_Component, Replace_Component, Escalate_Operator);
   type Fault is record
      Cluster_ID, Node_ID, Resource_ID, Boot_ID : Identity := Zero_Identity;
      Policy, Syndrome : Digest := Zero_Digest;
      Sequence, Observed_At, Expires_At : Counter := 0;
      Kind : Domain := Unknown_Domain;
      Level : Severity := Informational;
      Nature : Persistence := Transient;
      Quality : Evidence_Quality := Untrusted;
      Occurrences : Counter := 0;
      Corrected, Data_At_Risk, Execution_At_Risk : Boolean := False;
   end record;
   function Valid (F : Fault) return Boolean with Global => null;
   function Worse (Left, Right : Severity) return Severity with Global => null;
   function Isolation_Required (F : Fault) return Boolean with Global => null;
   function Automatic_Disposition (F : Fault) return Disposition with Global => null;
   -- Fault data is meaningful only after authenticating the observer/source and
   -- binding it to the current boot and policy. A signed observer statement is
   -- not automatically an attested hardware report.
end MC_Faults;
