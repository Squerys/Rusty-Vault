pub mod debugger;
pub mod timing;
pub mod memory;
pub mod exceptions;
pub mod handles;
pub mod assembly;
pub mod interactive;
pub mod misc;




pub fn run_all_checks() -> bool 
{
    if timing::check() 
    {
        return true;
    }

    if memory::check() 
    {
        return true;
    }

    if exceptions::check() 
    {
        return true;
    }

    if handles::check() 
    {
        return true;
    }

    if assembly::check() 
    {
        return true;
    }

    if interactive::check() 
    {
        return true;
    }

    if misc::check() 
    {
        return true;
    }

    false
}
