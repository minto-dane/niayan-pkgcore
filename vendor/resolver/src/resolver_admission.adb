-- SPDX-License-Identifier: MIT
package body Resolver_Admission with SPARK_Mode is
   procedure Check (U : Universe; A : Admission; Expected : Binding;
      Expected_Universe, Expected_Source, Expected_Plan, Expected_Reservation : Digest;
      Now, Required_Floor : Counter; Status : out Outcome) is
   begin
      Status := Denied;
      if not Well_Formed (U) or else not Binding_Valid (Expected) or else
        U.Subject /= Expected or else A.Subject /= Expected or else A.Count /= U.Item_Count or else
        Is_Zero (Expected_Universe) or else Is_Zero (Expected_Source) or else Is_Zero (Expected_Plan) or else
        Is_Zero (Expected_Reservation) or else A.Universe_Hash /= Expected_Universe or else
        A.Native_Source /= Expected_Source or else A.Physical_Plan /= Expected_Plan or else
        A.Reservation /= Expected_Reservation or else Now = 0 or else Now >= A.Expires or else
        Required_Floor = 0 or else A.Trust_Floor < Required_Floor then return; end if;
      for I in 1 .. U.Item_Count loop
         declare C : Coverage renames A.Items (I); begin
            if C.Artifact /= U.Items (I).Object_Hash or else C.Adapter /= U.Items (I).Adapter_Hash
              or else C.Source_Mark /= U.Items (I).Metadata_Hash or else Is_Zero (C.Evidence)
              or else C.Unsupported_Count /= 0 then return; end if;
            for D in Dimension loop
               -- An empty native dimension still needs a canonical digest of its
               -- empty authenticated inventory, not zero and not an omitted field.
               if Is_Zero (C.Observed (D)) or else C.Interpreted (D) /= C.Observed (D) then return; end if;
            end loop;
         end;
      end loop;
      Status := OK;
   end Check;
end Resolver_Admission;
