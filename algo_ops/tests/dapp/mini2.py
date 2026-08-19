import beaker
import pyteal as pt
from algokit_utils.config import config
from beaker import Application, localnet
from beaker.client import ApplicationClient


# Simple application with minimal state
class SimpleState:
    def __init__(self):
        pass

# Create the application
mini = Application("SimpleApp",
                        state=SimpleState(),
                        build_options=beaker.BuildOptions(scratch_slots=False))

@mini.external
def fn(x: pt.abi.Uint64, *, output: pt.abi.Uint64) -> pt.Expr:
    """Function that takes x and returns x*3 - 20"""
    return pt.Seq(
        output.set(x.get() * pt.Int(3) - pt.Int(20))
    )

# Override the update method to add creator authorization
@mini.update(bare=True, authorize=beaker.Authorize.only(pt.Global.creator_address()))
def update_app():
    """Update handler that only allows creator to update"""
    return pt.Approve()

@mini.delete(bare=True, authorize=beaker.Authorize.only(pt.Global.creator_address()))
def delete_app():
    """Delete handler that only allows creator to update"""
    return pt.Approve()

def demo() -> None:
    config.configure(debug=True)

    # Here we use `localnet` but beaker.client.api_providers can also be used
    # with something like ``AlgoNode(Network.TestNet).algod()``
    algod_client = localnet.get_algod_client()

    acct = localnet.get_accounts().pop()
    print(f"Account address: {acct.address}")
    print(f"Account balance before: {algod_client.account_info(acct.address)['amount']} microAlgos")

    # Create an Application client containing both an algod client and app
    app_client = ApplicationClient(
        client=algod_client, app=mini, signer=acct.signer
    )

    # Create the application on chain, implicitly sets the app id for the app client
    app_id, app_addr, txid = app_client.create()

    print(f"Created App with id: {app_id} and address addr: {app_addr} in tx: {txid}")

    print("All tests passed!")

if __name__ == "__main__":
    import sys
    
    # Check if 'demo' is passed as a command line argument
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo()
    else:
        # Default behavior: write out the data files
        mini2_spec = mini.build()
        # print out the results
        
        original_stdout = sys.stdout  # Save a reference to the original standard output
        
        with open('mini2_approval.teal', 'w') as f:
            sys.stdout = f  # Change the standard output to the file we created.
            print(mini2_spec.approval_program)
        
        sys.stdout = original_stdout  # Reset the standard output to its original value
        
        original_stdout = sys.stdout  # Save a reference to the original standard output

        with open('mini2_clear_state.teal', 'w') as f:
            sys.stdout = f  # Change the standard output to the file we created.
            print(mini2_spec.clear_program)
        
        sys.stdout = original_stdout  # Reset the standard output to its original value
        
        original_stdout = sys.stdout  # Save a reference to the original standard output

        with open('mini2_spec.json', 'w') as f:
            sys.stdout = f  # Change the standard output to the file we created.
            print(mini2_spec.to_json())
        
        sys.stdout = original_stdout  # Reset the standard output to its original value
        
        # Reset stdout
        sys.stdout = sys.__stdout__
        print("Data files written: mini2_approval.teal, mini2_clear_state.teal, mini2_spec.json")