// Password-only subset of upstream components/LoginPanel.tsx; keep its layout/classes.
import { Alert, Button, Card, Form, Input, Typography } from 'antd'
import { GithubOutlined } from '@ant-design/icons'
import { useEffect, useState } from 'react'
import { api, type Account } from './api'
import { ThemeToggle } from './ThemeToggle'
import { SiteFooter } from './SiteFooter'
export function LoginPanel({ onAuthSuccess, initialError }: { onAuthSuccess: (account: Account) => void; initialError?: string }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(initialError ?? '')
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [registrationEnabled, setRegistrationEnabled] = useState(false)
  const [form] = Form.useForm<{ email: string; password: string; code?: string }>()
  useEffect(() => {
    api<{ enabled: boolean }>('/auth/registration').then(result => setRegistrationEnabled(result.enabled)).catch(() => setRegistrationEnabled(false))
  }, [])
  async function submit(values: { email: string; password: string; code?: string }) {
    setLoading(true); setError('')
    try {
      const result = mode === 'register'
        ? await api<Account>('/auth/register', { email: values.email.trim(), password: values.password, code: values.code ?? '' })
        : await api<Account>('/auth/login', { email: values.email.trim(), password: values.password })
      form.resetFields(['password', 'code']); onAuthSuccess(result)
    } catch (err) {
      const message = err instanceof Error ? err.message : '登录失败，请重试。'
      setError(mode === 'register' && message === '账号或密码错误，请重试。' ? '注册码不正确。' : message)
    }
    finally { setLoading(false) }
  }
  return <><main className="auth-page">
    <div className="auth-language-menu"><a className="auth-github-link" href="https://github.com/liguobao/dsh-harness-remote" target="_blank" rel="noreferrer"><GithubOutlined /> GitHub</a><ThemeToggle className="auth-theme-toggle" /></div>
    <section className="auth-content">
      <div className="auth-logo-stack"><a className="auth-home-link" href="/" aria-label="返回首页"><img className="auth-brand-icon" src="/brand-whale.webp" alt="" width="48" height="48" /><Typography.Title>DeepSeek Harness Remote</Typography.Title></a></div>
      <Card className="auth-panel">
        <div className="auth-intro"><Typography.Title level={3} className="auth-title">{mode === 'register' ? '注册' : '登录'}</Typography.Title></div>
        {error && <Alert className="selfhost-auth-error" type="error" showIcon message={error} />}
        <Form form={form} layout="vertical" onFinish={submit} requiredMark={false} className="auth-form">
          <Form.Item name="email" label="账号" rules={[{ required: true, whitespace: true, message: '请输入账号' }, { max: 254, message: '账号不能超过 254 个字符' }]}><Input size="large" placeholder="请输入账号" autoComplete="username" /></Form.Item>
          <Form.Item name="password" label="密码" rules={[{ required: true, message: '请输入密码' }, ...(mode === 'register' ? [{ min: 12, message: '密码至少 12 个字符' }] : []), { max: 1024, message: '密码不能超过 1024 个字符' }]}><Input.Password size="large" placeholder={mode === 'register' ? '至少 12 个字符' : '请输入密码'} autoComplete={mode === 'register' ? 'new-password' : 'current-password'} /></Form.Item>
          {mode === 'register' && <Form.Item name="code" label="注册码" rules={[{ required: true, whitespace: true, message: '请输入注册码' }, { max: 256, message: '注册码过长' }]}><Input.Password size="large" placeholder="向管理员索取" autoComplete="off" /></Form.Item>}
          <Form.Item className="auth-submit-item"><Button loading={loading} block type="primary" size="large" htmlType="submit">{mode === 'register' ? '注册并进入' : '登录'}</Button></Form.Item>
          {registrationEnabled && <Button type="link" block onClick={() => { setMode(mode === 'register' ? 'login' : 'register'); setError('') }}>{mode === 'register' ? '已有账号？登录' : '没有账号？注册'}</Button>}
        </Form>
      </Card>
    </section>
  </main><SiteFooter /></>
}
