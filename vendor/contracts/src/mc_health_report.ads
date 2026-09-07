-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types; with MC_Time_Guard;
package MC_Health_Report with SPARK_Mode, Pure is
   type Condition is (Unknown_Health, Healthy, Starting, Failed, Stopped,
      Business_Failure, Integrity_Incident, Capacity_Incident);
   type Report is record
      Cluster_ID, Node_ID, Resource_ID, Invocation_ID : Identity:=Zero_Identity;
      Configuration, Recovery_Policy : Digest:=Zero_Digest;
      Stamp : MC_Time_Guard.Stamp;
      Result : Condition:=Unknown_Health;
      Config_Valid, Dependencies_Ready, Data_Compatible, Ownership_Exclusive : Boolean:=False;
      Business_Healthy, Maintenance, Emergency_Stop : Boolean:=False;
   end record;
   subtype Frame is Bytes(1..256);
   function Valid(R : Report) return Boolean with Global=>null;
   function Encode(R : Report) return Frame with Pre=>Valid(R), Global=>null;
   procedure Decode(B : Bytes; R : out Report; Status : out Outcome) with Global=>null;
   -- Authenticate the exact frame with MC_Authentic domain MC-HEALTH-v1 and an
   -- independently provisioned observer key before consuming any claim. No
   -- unsigned JSON boolean, self-signed requester assertion or PID-only "health".
end MC_Health_Report;
