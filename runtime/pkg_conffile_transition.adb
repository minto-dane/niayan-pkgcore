-- SPDX-License-Identifier: BSD-3-Clause
package body Pkg_Conffile_Transition with SPARK_Mode => Off is
   function Valid (Value : Image) return Boolean is
     (if Value.Kind = Missing then Value.Content = Zero_Digest
      elsif Value.Kind = Regular then Value.Content /= Zero_Digest else False);
   procedure Decide (Mode : Operation; Previously_Tracked : Boolean;
      Prior_Vendor, Current, Incoming : Image; Resolution : Choice;
      Result : out Decision; Status : out Outcome) is
      Local_Changed : Boolean;
   begin
      Result := (others => <>); Status := Unsupported;
      if Prior_Vendor.Kind = Other or else Current.Kind = Other or else Incoming.Kind = Other then return; end if;
      Status := Invalid_Input;
      if not Valid (Prior_Vendor) or else not Valid (Current) or else not Valid (Incoming)
        or else (not Previously_Tracked and then Prior_Vendor.Kind /= Missing)
        or else (Mode /= Install_Upgrade and then Incoming.Kind /= Missing) then return; end if;
      Result.Next_Vendor := (if Incoming.Kind = Regular then Incoming else Prior_Vendor);
      Result.Effect := Retain; Result.Content := Current.Content; Status := OK;
      if Mode = Remove_Package then return; end if;
      if Mode = Purge_Package then
         Result.Effect := Delete; Result.Content := Zero_Digest; Result.Next_Vendor := (others => <>); return;
      end if;
      Local_Changed := not Previously_Tracked or else Current /= Prior_Vendor;
      if Mode = Remove_On_Upgrade then
         -- The removal declaration and former vendor baseline remain tracked
         -- until purge; removing the active file does not erase its history.
         Result.Content := Zero_Digest;
         if Current.Kind = Missing then return; end if;
         if Local_Changed then
            Result.Effect := Backup_And_Delete; Result.Backup := Local_Backup; Result.Backup_Content := Current.Content;
         else Result.Effect := Delete;
         end if;
         return;
      end if;
      -- An omitted declaration/payload does not purge old configuration.
      if Incoming.Kind = Missing then
         -- Once neither the incoming package nor the filesystem has this path,
         -- the obsolete active baseline disappears. Generation history is separate.
         if Current.Kind = Missing then Result.Next_Vendor := (others => <>); end if;
         return;
      end if;
      if Current = Incoming then return; end if;
      if (not Previously_Tracked and then Current.Kind = Missing)
        or else (Previously_Tracked and then not Local_Changed) then
         Result.Effect := Replace; Result.Content := Incoming.Content; return;
      end if;
      if Previously_Tracked and then Prior_Vendor = Incoming then return; end if;
      case Resolution is
         when Unresolved =>
            Result := (others => <>); Result.Effect := Require_Choice;
         when Keep_Local =>
            Result.Backup := Vendor_Backup; Result.Backup_Content := Incoming.Content;
         when Use_Vendor =>
            Result.Effect := Replace; Result.Content := Incoming.Content;
            if Current.Kind = Regular then Result.Backup := Local_Backup; Result.Backup_Content := Current.Content; end if;
      end case;
   end Decide;
end Pkg_Conffile_Transition;
