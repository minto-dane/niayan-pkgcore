-- SPDX-License-Identifier: MIT
package body Pkg_System_Composition with SPARK_Mode is
   function Evaluate (C : Composition) return Assessment is
      Kernel_Index, Init_Count, Manager_Count, Libc_Count, Loader_Count, Recovery_Count : Natural := 0;
      Publisher_OK, Match : Boolean;
   begin
      if C.Plan = Zero_Digest or else C.Distribution = Zero_Digest or else C.Snapshot = Zero_Digest
        or else C.Count = 0 or else C.Publisher_Count = 0 or else C.Minimum_Trust = 0
        or else not C.Complete_Inventory then return Invalid_Set; end if;
      if not C.Dependency_Closure_Checked or else not C.Ownership_Checked
        or else not C.Data_Migrations_Checked or else not C.Secure_Boot_Path_Checked
      then return Unchecked_Effects; end if;
      for I in 1 .. C.Publisher_Count loop
         if C.Publishers (I) = Zero_Digest then return Invalid_Set; end if;
         for J in 1 .. I-1 loop if C.Publishers (I) = C.Publishers (J) then return Invalid_Set; end if; end loop;
      end loop;
      for I in 1 .. C.Count loop
         declare A : Artifact renames C.Artifacts (I); begin
            Publisher_OK := False;
            for K in 1 .. C.Publisher_Count loop if A.Publisher = C.Publishers (K) then Publisher_OK := True; end if; end loop;
            if A.Object_Digest = Zero_Digest or else A.Payload = Zero_Digest or else A.ABI = Zero_Digest
              or else not Publisher_OK or else not A.Signature_Admitted
              or else A.Trust_Epoch < C.Minimum_Trust or else A.Distribution /= C.Distribution
              or else A.Snapshot /= C.Snapshot then return Unauthenticated_Artifact; end if;
            if not A.Effects_Covered or else not A.Recovery_Pinned then return Unchecked_Effects; end if;
            for J in 1 .. I-1 loop if A.Object_Digest = C.Artifacts (J).Object_Digest then return Invalid_Set; end if; end loop;
            case A.Kind is
               when Kernel =>
                  if Kernel_Index /= 0 then return Incompatible_Cohort; end if; Kernel_Index := I;
               when Initramfs => Init_Count := Init_Count+1;
               when Service_Manager => Manager_Count := Manager_Count+1;
               when C_Library => Libc_Count := Libc_Count+1;
               when Boot_Loader => Loader_Count := Loader_Count+1;
               when Recovery_Image => Recovery_Count := Recovery_Count+1;
               when others => null;
            end case;
         end;
      end loop;
      if Kernel_Index = 0 or else Init_Count /= 1 or else Manager_Count /= 1
        or else Libc_Count /= 1 or else Loader_Count = 0 or else Recovery_Count = 0
      then return Missing_Foundation; end if;
      for I in 1 .. C.Count loop
         declare A : Artifact renames C.Artifacts (I); begin
            if A.Kind in Initramfs | Kernel_Module then
               if A.Target_Kernel /= C.Artifacts (Kernel_Index).Object_Digest
                 or else A.ABI /= C.Artifacts (Kernel_Index).ABI then return Incompatible_Cohort; end if;
            end if;
            if A.Driver_ABI /= Zero_Digest then
               if A.Kind not in Kernel_Module | Driver_Userspace then return Invalid_Set; end if;
               Match := False;
               for J in 1 .. C.Count loop
                  if A.Driver_ABI = C.Artifacts (J).Driver_ABI
                    and then ((A.Kind = Kernel_Module and then C.Artifacts (J).Kind = Driver_Userspace)
                      or else (A.Kind = Driver_Userspace and then C.Artifacts (J).Kind = Kernel_Module))
                  then Match := True; end if;
               end loop;
               if not Match then return Incompatible_Cohort; end if;
            elsif A.Kind = Driver_Userspace then return Incompatible_Cohort;
            end if;
         end;
      end loop;
      return Admissible;
   end Evaluate;
end Pkg_System_Composition;
