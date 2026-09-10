-- SPDX-License-Identifier: BSD-3-Clause
with Ada.Unchecked_Deallocation;
with MC_SHA256; with Resolver_Wire; with Resolver_Verify;
package body Pkg_Resolution_Engine with SPARK_Mode => Off is
   use type Resolver_Model.Check_Code;
   type Universe_Access is access Resolver_Model.Universe;
   type Proposal_Access is access Resolver_Model.Proposal;
   type Admission_Access is access Resolver_Admission.Admission;
   type Buffer_Access is access Bytes;
   procedure Free_U is new Ada.Unchecked_Deallocation (Resolver_Model.Universe, Universe_Access);
   procedure Free_P is new Ada.Unchecked_Deallocation (Resolver_Model.Proposal, Proposal_Access);
   procedure Free_A is new Ada.Unchecked_Deallocation (Resolver_Admission.Admission, Admission_Access);
   procedure Free_B is new Ada.Unchecked_Deallocation (Bytes, Buffer_Access);
   procedure Guard (Root_ID, Transaction_ID : Identity; Plan, Evidence : Digest;
      Epoch, Fence : Counter; Phase : String; Status : out Outcome) is
      U : Universe_Access := null; P : Proposal_Access := null;
      A : Admission_Access := null; B : Buffer_Access := null;
      Expected : Resolver_Model.Binding; H, Source, Reservation : Digest;
      Now, Floor : Counter; Used : Natural; Fuel : Natural := Resolver_Verify.Default_Fuel;
      R : Resolver_Model.Report;
      procedure Release is
      begin Free_U (U); Free_P (P); Free_A (A); Free_B (B); end;
   begin
      Status := Denied;
      if Phase not in "prepare" | "capture" | "apply" | "commit" | "restore" |
        "file-effect" | "publish-file" | "finish-terminal" | "repair-journal" then return; end if;
      Authorize (Root_ID, Transaction_ID, Plan, Evidence, Epoch, Fence, Phase, Status);
      if Status /= OK then return; end if;
      U := new Resolver_Model.Universe; P := new Resolver_Model.Proposal;
      A := new Resolver_Admission.Admission;
      Observe (Root_ID, Transaction_ID, Plan, Phase, U.all, P.all, A.all, Expected, H,
         Source, Reservation, Now, Floor, Status);
      if Status /= OK then Release; return; end if;
      -- Catalog/model generation and cluster membership epoch are distinct
      -- namespaces. The independently obtained binding is checked by Admission,
      -- native source/physical-plan revalidation and Recheck_Current, NOT equated
      -- to Origin_Epoch. A restore requires a new reverse model and admission.
      if Expected.Root /= MC_SHA256.Hash (Root_ID) then
         Status := Denied; Release; return;
      end if;
      B := new Bytes (1 .. Resolver_Wire.Maximum_Universe_Bytes);
      Resolver_Wire.Encode (U.all, B.all, Used, Status);
      if Status = OK and then MC_SHA256.Hash (B (1 .. Used)) /= H then Status := Denied; end if;
      if Status /= OK then Release; return; end if;
      Resolver_Admission.Check (U.all, A.all, Expected, H, Source, Plan, Reservation, Now, Floor, Status);
      if Status /= OK then Release; return; end if;
      Resolver_Verify.Check_Schedule (U.all, H, P.all, R, Fuel);
      if R.Code /= Resolver_Model.Valid_Schedule then
         Status := (if R.Code = Resolver_Model.Limit_Reached then Exhausted else Denied);
         Release; return;
      end if;
      Check_Native (U.all, P.all, Source, Plan, Reservation, Phase, Status);
      if Status /= OK then Release; return; end if;
      Recheck_Current (Expected, H, Source, Plan, Reservation, A.Expires, A.Trust_Floor, Status);
      if Status /= OK then Release; return; end if;
      -- Do not equate a solver answer, model check or proof with live authority.
      Authorize (Root_ID, Transaction_ID, Plan, Evidence, Epoch, Fence, Phase, Status);
      Release;
   exception
      when others => Release; Status := IO_Error;
   end Guard;
end Pkg_Resolution_Engine;
