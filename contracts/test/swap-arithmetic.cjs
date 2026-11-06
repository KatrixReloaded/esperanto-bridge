const {setup,price,swap,balances,assert,rejects} = require('./swap-helpers.cjs');
const MAX=(1n<<64n)-1n;
const DEN=10n**18n;
describe('XMR12 to cUSDC6 bounded arithmetic',function(){
  for(const [name,input,p,paid] of [
    ['one XMR at $50 less 1 percent',10n**12n,5000000000n,49500000n],
    ['rounds fractional micro-USDC down',1000000000001n,5000000001n,49500000n],
    ['dust rejects',1n,1n,0n],
    ['full uint64 input at maximum price',MAX,100000000000000n,MAX*9900n/10000n],
    ['largest input small price',MAX,1n,MAX*9900n/DEN],
  ]) it(name,async function(){
    const f=await setup(false,MAX,input); await price(f,p); await swap(f,input);
    await balances(f,paid?0n:input,paid,paid?input:0n,MAX-paid);
  });
  it('accepts exactly uint64 max output at the price ceiling with zero fee',async function(){
    const f=await setup(false,MAX,MAX,0); await price(f,100000000000000n); await swap(f,MAX);
    await balances(f,0n,MAX,MAX,0n);
  });
  it('includes 12 input decimals, 8 price decimals, 6 output decimals and basis points',async function(){
    const f=await setup(); const [n,d]=await f.pool.rate(f.signed.quote,f.signed.signature);
    assert.equal(n,5000000000n*9900n); assert.equal(d,DEN);
    for(const input of [1n,1000000000001n,MAX]) {
      assert.equal(input*n/d, input*5000000000n*9900n*10n**6n/(10n**12n*10n**8n*10000n));
    }
  });
  it('rejects the old 8-decimal token configuration',async function(){
    const f=await setup();
    const old=await(await require('hardhat').ethers.getContractFactory('MockUSDC')).deploy(8);
    const b=await(await require('hardhat').ethers.getContractFactory('SwapReceiverMock')).deploy(old.target);
    const factory=await require('hardhat').ethers.getContractFactory('CWXMRSwap');
    await rejects(()=>factory.deploy(old.target,f.cusdc.target,b.target,f.quoteWallet.address,100),'InvalidConfiguration');
  });
});
