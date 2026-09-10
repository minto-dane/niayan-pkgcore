-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
package MC_Accounting with SPARK_Mode, Pure is
   type Event_Kind is
     (Change_Requested, Change_Authorized, Change_Started, Change_Completed,
      Change_Rejected, Generation_Accepted, Generation_Committed,
      Incident_Opened, Incident_Contained, Incident_Closed,
      Fault_Observed, Node_Drained, Node_Fenced, Node_Readmitted,
      Backup_Created, Restore_Tested, Recovery_Invoked,
      Breakglass_Requested, Breakglass_Authorized, Policy_Changed,
      Trust_Rotated, Security_Denial);
   type Importance is (Informational, Operational, Security, Critical);
   type Event is record
      Event_ID, Scope, Object_ID, Actor, Correlation_ID : Identity := Zero_Identity;
      Payload, Policy, Previous_Record, Remote_Receipt : Digest := Zero_Digest;
      Sequence, Observed_At, Trust_Epoch : Counter := 0;
      Kind : Event_Kind := Change_Requested;
      Level : Importance := Informational;
      Authenticated, Remotely_Preserved, Immutable_Receipt : Boolean := False;
   end record;
   function Valid (E : Event) return Boolean with Global=>null;
   function Chain_Extends (Previous_Digest : Digest; Previous_Sequence : Counter; E : Event) return Boolean with Global=>null;
   function Required_Remote_Preservation (E : Event) return Boolean with Global=>null;
end MC_Accounting;
