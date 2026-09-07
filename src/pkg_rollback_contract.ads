-- SPDX-License-Identifier: MIT
with MC_Types; use MC_Types;
package Pkg_Rollback_Contract with SPARK_Mode, Pure is
   type Migration_Kind is (None, Reversible, Forward_Compatible, Irreversible);
   type Contract is record
      Package_ID, From_State, To_State, Reverse_Procedure : Digest := Zero_Digest;
      Data_Schema_From, Data_Schema_To : Counter := 0;
      Config_Migration, Data_Migration : Migration_Kind := None;
      Old_Binary_Reads_New_Data, New_Binary_Reads_Old_Data : Boolean := False;
      Restore_Required_For_Reverse, Restore_Verified : Boolean := False;
   end record;
   type Decision is (Live_Rollback, Coordinated_Rollback, Restore_Rollback, Not_Reversible, Invalid);
   function Evaluate (C : Contract) return Decision with Global=>null;
end Pkg_Rollback_Contract;
