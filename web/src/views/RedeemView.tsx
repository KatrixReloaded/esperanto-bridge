import type { Balance } from '../hooks/useBalance'
import type { BridgeInfoState } from '../hooks/useBridgeInfo'
import type { Redeem } from '../hooks/useRedeem'
import type { Wallet } from '../hooks/useWallet'
import { BalanceRow } from '../components/BalanceRow'
import { ErrorMsg, ExplorerLink, Panel, PollNotice, Progress, Section } from '../components/ui'
import { REDEEM_STEPS, redeemStage } from '../lib/status'
import { formatAtomic } from '../lib/amount'
import { explorerTx } from '../config'
type Props = { r: Redeem; wallet: Wallet; balance: Balance; bridge: BridgeInfoState; onConnect: () => void }
export function RedeemView({ r, wallet, balance, bridge }: Props) {
  const stage = r.status.data && redeemStage(r.status.data)
  const uncertain = ['unknown', 'unfinished', 'noEvent'].includes(r.phase)
  return <div className="cw-grid"><div className="cw-col"><Section i={0}><BalanceRow balance={balance} connected={wallet.connected}/></Section>
    <Section i={1}><div className="fld"><label className="lbl" htmlFor="amount">Amount (cwXMR)</label><input id="amount" className="inp" inputMode="decimal" value={r.amt} disabled={r.locked} onChange={e => r.editAmount(e.target.value)} onBlur={r.blurAmount}/>{r.amtErr && <ErrorMsg>{r.amtErr}</ErrorMsg>}</div></Section>
    <Section i={2}><div className="fld"><label className="lbl" htmlFor="destination">Monero stagenet address</label><textarea id="destination" className="inp mono ta" autoComplete="off" spellCheck={false} value={r.destination} disabled={r.locked} onChange={e => r.editDestination(e.target.value)} onBlur={r.blurDestination}/>{r.destinationErr && <ErrorMsg>{r.destinationErr}</ErrorMsg>}</div></Section>
    <Section i={3}><dl className="dl"><div className="dl-row"><dt>Fee</dt><dd>{bridge.feeAtomic == null ? 'Unavailable' : `${formatAtomic(bridge.feeAtomic)} XMR`}</dd></div></dl>{r.phase === 'idle' && <button className="btn btn-p btn-full" disabled={!!r.blockReason || !wallet.connected} onClick={() => { if (r.validate()) r.start() }}>Request redemption</button>}{['prepareFailed', 'cancelled', 'mismatch'].includes(r.phase) && <button className="btn btn-s" disabled={!!r.blockReason} onClick={r.retry}>Retry this request</button>}{r.phase !== 'idle' && <Panel kind={uncertain ? 'alert' : 'info'} title={uncertain ? 'Check transaction status' : `Request: ${r.phase}`} detail={uncertain ? 'Check wallet activity. Do not submit again.' : undefined}/>} {['reverted', 'invalid'].includes(r.phase) && <button className="btn btn-s" onClick={r.reset}>Start another request</button>}{r.blockReason && <div className="help">{r.blockReason}</div>}{r.intent?.hash && <ExplorerLink href={explorerTx(r.intent.hash)} hash={r.intent.hash} what="Redemption"/>}</Section>
  </div><div className="cw-col"><Section i={4}><div className="fld"><label className="lbl" htmlFor="request-id">Track request ID</label><input id="request-id" className="inp" value={r.idInput} onChange={e => r.editId(e.target.value)}/>{r.idErr && <ErrorMsg>{r.idErr}</ErrorMsg>}<button className="btn btn-s" onClick={() => { if (r.validateId()) r.startTrackId() }}>Track</button>{r.trackedId && <><div className="help">Request #{r.trackedId}</div><PollNotice poll={r.status}/>{stage?.kind === 'progress' && <Progress label="Redemption progress" steps={REDEEM_STEPS} current={stage.step} detail={stage.detail}/>} {stage?.kind === 'panel' && <Panel kind={stage.panel} title={stage.title} detail={stage.detail}/>} {stage?.kind === 'done' && <Panel kind="check" title="XMR payout recorded"/>}</>}</div></Section></div></div>
}
