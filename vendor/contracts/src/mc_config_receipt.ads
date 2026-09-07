-- SPDX-License-Identifier: MIT
with MC_Types;use MC_Types;
package MC_Config_Receipt with SPARK_Mode,Pure is
   Version : constant:=1;Wire_Size : constant:=512;
   type Phase is (Before_Apply,Before_Activation,Accept_Running,Before_Restore);
   type Subject is record
      Root,Transaction,Boot : Identity:=Zero_Identity;
      Plan,Target_Set,Effective_Config,Source_Inventory,Input_State,Generated_Set,
        Adapter_Set,Validator_Set,Policy,Contract,Report : Digest:=Zero_Digest;
      Generation,Epoch,Sequence : Counter:=0;
      Scope : Phase:=Before_Apply;
   end record;
   type Receipt is record
      Binding : Subject;Observed_At,Not_Before,Expires : Counter:=0;
      Complete_Inputs,Native_Validated,Constraints_Passed,Derived_Current,
        Running_Exact,Rollback_Compatible : Boolean:=False;
   end record;
   subtype Wire is Bytes(1..Wire_Size);
   function Valid(R : Receipt) return Boolean with Global=>null;
   procedure Encode(R : Receipt;B : out Wire;Status : out Outcome) with Global=>null;
   procedure Decode(B : Bytes;R : out Receipt;Status : out Outcome) with Global=>null;
   procedure Check(R : Receipt;Expected : Subject;Now,Minimum_Sequence,Max_Age,Max_Lifetime : Counter;
      Status : out Outcome) with Global=>null;
   -- Check is a pure predicate, NOT cryptographic verification. Input_State must
   -- be reobserved with the writer reservation held. Boot/epoch/phase are exact.
   -- Sequence floor is held in independent rollback-resistant state by the caller.
end MC_Config_Receipt;
