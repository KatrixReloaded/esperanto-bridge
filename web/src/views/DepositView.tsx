import type { Balance } from '../hooks/useBalance'
import type { BridgeInfoState } from '../hooks/useBridgeInfo'
import type { Deposit } from '../hooks/useDeposit'
import type { Wallet } from '../hooks/useWallet'
import { BalanceRow } from '../components/BalanceRow'
import { CopyTextButton, Panel, PollNotice, Progress, Section } from '../components/ui'
import { DEPOSIT_STEPS, depositStage } from '../lib/status'
import { DEMO } from '../config'
type Props = { d: Deposit; wallet: Wallet; balance: Balance; bridge: BridgeInfoState; onConnect: () => void }
export function DepositView({ d, wallet, balance, onConnect }: Props) {
  const record = d.status.data ?? d.issued
  const stage = record && depositStage(record)
  return <div className="cw-grid"><div className="cw-col">
    <Section i={0}><div className="fld"><span className="lbl">Receive cwXMR on Sepolia</span><output className="ro-box">{wallet.address ?? 'Connect your recipient wallet'}</output></div></Section>
    <Section i={1}><div className="fld"><span className="lbl">Send stagenet XMR</span>{d.issued ? <><div className="val mono">{d.issued.depositAddress}</div><CopyTextButton text={d.issued.depositAddress} label="Copy address"/><div className="help">{DEMO ? 'Demo address — do not send funds.' : 'Stagenet only.'}</div></> : <><div className="val empty">No deposit address yet</div>{!wallet.connected ? <button className="btn btn-p" onClick={onConnect}>Connect wallet</button> : <button className="btn btn-p" disabled={!!d.blockReason || d.busy} onClick={d.create}>{d.busy ? 'Generating…' : 'Generate address'}</button>}</>}{d.blockReason && <div className="help">{d.blockReason}</div>}{d.error && <Panel kind="alert" title={d.error}/>}</div></Section>
    <Section i={2}><BalanceRow balance={balance} connected={wallet.connected}/></Section>
  </div><div className="cw-col"><Section i={3}><div className="fld"><span className="lbl">Deposit progress</span>{record ? <><PollNotice poll={d.status}/>{stage?.kind === 'progress' && <Progress label="Deposit progress" steps={DEPOSIT_STEPS} current={stage.step} detail={stage.detail}/>} {stage?.kind === 'done' && <Panel kind="check" title="Mint complete"/>}{stage?.kind === 'panel' && <Panel kind={stage.panel} title={stage.title} detail={stage.detail}/>}<CopyTextButton text={record.intentId} label="Copy private intent ID"/></> : <Panel kind="info" title="No deposit yet"/>}</div></Section>
    <Section i={4}><div className="fld"><label className="lbl" htmlFor="deposit-intent-id">Resume a deposit</label><input id="deposit-intent-id" className="inp mono" type="password" autoComplete="off" spellCheck={false} value={d.savedIntentId} disabled={d.busy} onChange={e => d.editSavedIntentId(e.target.value)} placeholder="Private intent ID"/><div className="help">Use the same recipient wallet.</div><button className="btn btn-s" disabled={!!d.blockReason || d.busy || !d.savedIntentId} onClick={d.resume}>Resume tracking</button></div></Section>
    </div></div>
}
