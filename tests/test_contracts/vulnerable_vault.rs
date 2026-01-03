use anchor_lang::prelude::*;
use anchor_lang::solana_program::{program, instruction::Instruction};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod vulnerable_defi {
    use super::*;

    // ====================================================
    // BUG 1: MISSING SIGNER (Core Pattern)
    // Vulnerability: Anyone can call this and overwrite the admin!
    // ====================================================
    pub fn initialize_protocol(ctx: Context<Initialize>, new_admin: Pubkey) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.admin = new_admin; // OOPS: No check that the current admin signed!
        state.fee = 0;
        Ok(())
    }

    // ====================================================
    // BUG 2: PRECISION LOSS (Core Pattern)
    // Vulnerability: Division before multiplication results in 0 fees.
    // ====================================================
    pub fn collect_fees(ctx: Context<CollectFees>, amount: u64) -> Result<()> {
        // Example: 50 / 100 = 0. 0 * 10 = 0. Protocol gets nothing.
        let fee = (amount / 100) * ctx.accounts.state.fee;
        
        msg!("Collecting fee: {}", fee);
        Ok(())
    }

    // ====================================================
    // BUG 3: UNSAFE CPI (Core Pattern)
    // Vulnerability: Raw invoke allows calling a malicious program.
    // ====================================================
    pub fn emergency_withdraw(ctx: Context<UnsafeWithdraw>, amount: u64) -> Result<()> {
        // The user passes 'token_program' as an AccountInfo. 
        // We blindly trust it and invoke it.
        let ix = Instruction {
            program_id: *ctx.accounts.token_program.key,
            accounts: vec![],
            data: vec![],
        };
        program::invoke(&ix, &[ctx.accounts.token_program.clone()])?;
        Ok(())
    }

    // ====================================================
    // BUG 4: BAD OWNER / UNSAFE ACCOUNT (Core Pattern)
    // Vulnerability: 'vault' is just AccountInfo. Could be a fake account.
    // ====================================================
    pub fn deposit_assets(ctx: Context<UnsafeDeposit>, amount: u64) -> Result<()> {
        msg!("Depositing {} to vault {:?}", amount, ctx.accounts.vault.key);
        // We assume 'vault' is our token account, but we never checked the owner!
        Ok(())
    }

    // ====================================================
    // BUG 5: MISSING BUMP CHECK (Core Pattern)
    // Vulnerability: Seeds are used, but canonical bump is not verified.
    // ====================================================
    pub fn create_user_profile(ctx: Context<BadPda>) -> Result<()> {
        msg!("Profile created");
        Ok(())
    }

    // ====================================================
    // EXTRA BUG 6: ARBITRARY LOGIC (Logic Error)
    // Vulnerability: No limit on fee. Admin can set fee to 10000%.
    // ====================================================
    pub fn set_fee(ctx: Context<UpdateState>, new_fee: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        // MISSING CHECK: if new_fee > 100 { return err; }
        state.fee = new_fee; 
        Ok(())
    }

    // ====================================================
    // EXTRA BUG 7: UNCONSTRAINED CLOSING (Solana Specific)
    // Vulnerability: Closing an account and sending lamports to ANYONE.
    // ====================================================
    pub fn close_account(ctx: Context<CloseAccount>) -> Result<()> {
        // The 'destination' account has no constraints. 
        // An attacker could trick the admin into closing the state 
        // and sending the rent lamports to the attacker's wallet.
        Ok(())
    }
}

// --------------------------------------------------------
// CONTEXT STRUCTS
// --------------------------------------------------------

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = user, space = 8 + 40)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub user: Signer<'info>, 
    pub system_program: Program<'info, System>,
    // BUG 1 SOURCE: The 'authority' should be a Signer, but it's not here!
}

#[derive(Accounts)]
pub struct CollectFees<'info> {
    pub state: Account<'info, State>,
}

#[derive(Accounts)]
pub struct UnsafeWithdraw<'info> {
    /// CHECK: This is unsafe!
    pub token_program: AccountInfo<'info>, 
}

#[derive(Accounts)]
pub struct UnsafeDeposit<'info> {
    /// CHECK: BUG 4 SOURCE: No owner check, no type check.
    pub vault: AccountInfo<'info>, 
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct BadPda<'info> {
    // BUG 5 SOURCE: seeds used, but no 'bump' constraint!
    #[account(
        init, 
        payer = user, 
        space = 8 + 8,
        seeds = [b"profile", user.key().as_ref()]
    )]
    pub profile: Account<'info, UserProfile>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateState<'info> {
    #[account(mut, has_one = admin)]
    pub state: Account<'info, State>,
    pub admin: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseAccount<'info> {
    #[account(mut, close = destination)]
    pub state: Account<'info, State>,
    /// CHECK: BUG 7 SOURCE: Who is this? It could be anyone.
    #[account(mut)]
    pub destination: AccountInfo<'info>, 
    pub admin: Signer<'info>,
}

// --------------------------------------------------------
// DATA LAYOUTS
// --------------------------------------------------------

#[account]
pub struct State {
    pub admin: Pubkey,
    pub fee: u64,
}

#[account]
pub struct UserProfile {
    pub points: u64,
}