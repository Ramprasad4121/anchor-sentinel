use anchor_lang::prelude::*;

#[program]
pub mod token_2022_vulnerable {
    use super::*;
    use spl_token_2022::extension::ExtensionType;

    // V007: Permanent Delegate usage
    pub fn init_dangerous_delegate(ctx: Context<Init>, delegate: Pubkey) -> Result<()> {
        let x = ExtensionType::PermanentDelegate;
        msg!("Initializing permanent delegate: {:?}", delegate);
        Ok(())
    }

    // V007: Transfer Hook without reentrancy guard
    #[interface(spl_transfer_hook_interface::execute)]
    pub fn transfer_hook(ctx: Context<TransferHook>, amount: u64) -> Result<()> {
        // No #[reentrancy_guard] here!
        msg!("Executing transfer hook with amount: {}", amount);
        Ok(())
    }
}
