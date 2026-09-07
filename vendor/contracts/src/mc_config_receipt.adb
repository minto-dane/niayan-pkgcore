-- SPDX-License-Identifier: MIT
with MC_Codec;
package body MC_Config_Receipt with SPARK_Mode is
   use type Byte;use type Wide;
   Magic : constant Bytes:=(16#4D#,16#43#,16#43#,16#46#,16#47#,16#30#,16#30#,16#31#);
   function Valid(R : Receipt) return Boolean is
      B : constant Subject:=R.Binding;
   begin
      return B.Root/=Zero_Identity and then B.Transaction/=Zero_Identity and then B.Boot/=Zero_Identity and then
        B.Plan/=Zero_Digest and then B.Target_Set/=Zero_Digest and then B.Effective_Config/=Zero_Digest and then
        B.Source_Inventory/=Zero_Digest and then B.Input_State/=Zero_Digest and then B.Generated_Set/=Zero_Digest and then
        B.Adapter_Set/=Zero_Digest and then B.Validator_Set/=Zero_Digest and then B.Policy/=Zero_Digest and then
        B.Contract/=Zero_Digest and then B.Report/=Zero_Digest and then B.Generation>0 and then B.Epoch>0 and then
        B.Sequence>0 and then R.Not_Before<=R.Observed_At and then R.Observed_At<R.Expires and then
        R.Complete_Inputs and then R.Native_Validated and then R.Constraints_Passed and then
        (B.Scope not in Before_Activation|Accept_Running or else R.Derived_Current) and then
        (B.Scope/=Accept_Running or else R.Running_Exact) and then
        (B.Scope/=Before_Restore or else R.Rollback_Compatible);
   end Valid;
   procedure Encode(R : Receipt;B : out Wire;Status : out Outcome) is
      Bits : Byte:=0;
   begin
      B:=(others=>0);Status:=Invalid_Input;if not Valid(R) then return;end if;
      B(1..8):=Magic;B(9..24):=R.Binding.Root;B(25..40):=R.Binding.Transaction;B(41..56):=R.Binding.Boot;
      B(57..88):=R.Binding.Plan;B(89..120):=R.Binding.Target_Set;B(121..152):=R.Binding.Effective_Config;
      B(153..184):=R.Binding.Source_Inventory;B(185..216):=R.Binding.Input_State;B(217..248):=R.Binding.Generated_Set;
      B(249..280):=R.Binding.Adapter_Set;B(281..312):=R.Binding.Validator_Set;B(313..344):=R.Binding.Policy;
      B(345..376):=R.Binding.Contract;B(377..408):=R.Binding.Report;
      MC_Codec.Put64(B,409,Wide(R.Binding.Generation));MC_Codec.Put64(B,417,Wide(R.Binding.Epoch));
      MC_Codec.Put64(B,425,Wide(R.Binding.Sequence));MC_Codec.Put64(B,433,Wide(R.Observed_At));
      MC_Codec.Put64(B,441,Wide(R.Not_Before));MC_Codec.Put64(B,449,Wide(R.Expires));
      B(457):=Byte(Phase'Pos(R.Binding.Scope)+1);
      if R.Complete_Inputs then Bits:=Bits+1;end if;if R.Native_Validated then Bits:=Bits+2;end if;
      if R.Constraints_Passed then Bits:=Bits+4;end if;if R.Derived_Current then Bits:=Bits+8;end if;
      if R.Running_Exact then Bits:=Bits+16;end if;if R.Rollback_Compatible then Bits:=Bits+32;end if;
      B(458):=Bits;Status:=OK;
   end Encode;
   procedure Decode(B : Bytes;R : out Receipt;Status : out Outcome) is
      W,Canonical : Wire;T : Receipt;N : Wide;Local : Outcome;
      function Count(P : Positive) return Counter is (Counter(MC_Codec.U64(W,P)));
   begin
      R:=(others=><>);Status:=Invalid_Input;if B'Length/=Wire_Size then return;end if;W:=B;
      if W(1..8)/=Magic or else W(457) not in 1..4 or else W(458)>63 then return;end if;
      for I in 459..512 loop if W(I)/=0 then return;end if;end loop;
      for I in 0..5 loop N:=MC_Codec.U64(W,409+I*8);if N>Wide(Counter'Last) then return;end if;end loop;
      T.Binding.Root:=W(9..24);T.Binding.Transaction:=W(25..40);T.Binding.Boot:=W(41..56);
      T.Binding.Plan:=W(57..88);T.Binding.Target_Set:=W(89..120);T.Binding.Effective_Config:=W(121..152);
      T.Binding.Source_Inventory:=W(153..184);T.Binding.Input_State:=W(185..216);T.Binding.Generated_Set:=W(217..248);
      T.Binding.Adapter_Set:=W(249..280);T.Binding.Validator_Set:=W(281..312);T.Binding.Policy:=W(313..344);
      T.Binding.Contract:=W(345..376);T.Binding.Report:=W(377..408);
      T.Binding.Generation:=Count(409);T.Binding.Epoch:=Count(417);T.Binding.Sequence:=Count(425);
      T.Observed_At:=Count(433);T.Not_Before:=Count(441);T.Expires:=Count(449);
      T.Binding.Scope:=Phase'Val(Natural(W(457))-1);
      T.Complete_Inputs:=(W(458) and 1)/=0;T.Native_Validated:=(W(458) and 2)/=0;
      T.Constraints_Passed:=(W(458) and 4)/=0;T.Derived_Current:=(W(458) and 8)/=0;
      T.Running_Exact:=(W(458) and 16)/=0;T.Rollback_Compatible:=(W(458) and 32)/=0;
      Encode(T,Canonical,Local);if Local/=OK or else Canonical/=W then return;end if;
      R:=T;Status:=OK;
   end Decode;
   procedure Check(R : Receipt;Expected : Subject;Now,Minimum_Sequence,Max_Age,Max_Lifetime : Counter;
      Status : out Outcome) is
   begin
      Status:=Denied;
      if not Valid(R) or else R.Binding/=Expected or else Max_Age=0 or else Max_Lifetime=0 or else
        Minimum_Sequence=0 or else R.Binding.Sequence<Minimum_Sequence or else R.Not_Before>Now or else R.Observed_At>Now or else
        Now>=R.Expires or else R.Expires-R.Not_Before>Max_Lifetime then return;end if;
      if Now-R.Observed_At>Max_Age then Status:=Stale;return;end if;
      Status:=OK;
   end Check;
end MC_Config_Receipt;
