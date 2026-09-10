-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Rollback_Contract with SPARK_Mode is
   function Evaluate (C : Contract) return Decision is
   begin
      if C.Package_ID=Zero_Digest or else C.From_State=Zero_Digest or else C.To_State=Zero_Digest
        or else C.Data_Schema_To<C.Data_Schema_From then return Invalid; end if;
      if C.Data_Migration=Irreversible or else C.Config_Migration=Irreversible then
         if C.Restore_Required_For_Reverse and then C.Restore_Verified then return Restore_Rollback; end if;
         return Not_Reversible;
      end if;
      if C.Data_Migration=None and then C.Config_Migration=None then return Live_Rollback; end if;
      if C.Data_Migration in None | Reversible and then C.Config_Migration in None | Reversible
        and then C.Reverse_Procedure/=Zero_Digest then return Coordinated_Rollback; end if;
      if C.Old_Binary_Reads_New_Data and then C.New_Binary_Reads_Old_Data then return Coordinated_Rollback; end if;
      if C.Restore_Required_For_Reverse and then C.Restore_Verified then return Restore_Rollback; end if;
      return Not_Reversible;
   end Evaluate;
end Pkg_Rollback_Contract;
