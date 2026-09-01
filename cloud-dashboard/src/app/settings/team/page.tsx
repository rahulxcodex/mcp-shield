'use client';

import { useState, useEffect } from 'react';
import { UserPlus, Shield, ShieldAlert, User, Loader2 } from 'lucide-react';

interface Member {
  id: string;
  user_id: string;
  role: string;
}

export default function TeamPage() {
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('viewer');
  const [members, setMembers] = useState<Member[]>([]);
  const [orgId, setOrgId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isInviting, setIsInviting] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    async function loadData() {
      try {
        const orgRes = await fetch('/api/v1/organizations');
        const orgs = await orgRes.json();
        if (orgs.length > 0) {
          const id = orgs[0].id;
          setOrgId(id);
          
          const memRes = await fetch(`/api/v1/organizations/${id}/members`);
          const memData = await memRes.json();
          setMembers(memData);
        } else {
          // Auto create an org if none exists
          const createRes = await fetch('/api/v1/organizations', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: 'My Workspace', slug: 'my-workspace-' + Date.now() })
          });
          if (createRes.ok) {
            const newOrg = await createRes.json();
            setOrgId(newOrg.id);
            setMembers([{ id: 'new', user_id: 'You', role: 'owner' }]);
          }
        }
      } catch (err) {
        console.error(err);
      } finally {
        setIsLoading(false);
      }
    }
    loadData();
  }, []);

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId) return;
    
    setIsInviting(true);
    setMessage('');
    try {
      const res = await fetch(`/api/v1/organizations/${orgId}/members`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, role })
      });
      
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Failed to invite');
      }
      
      const newMember = await res.json();
      setMembers([...members, newMember]);
      setEmail('');
      setMessage('User successfully invited!');
    } catch (err: any) {
      setMessage(err.message);
    } finally {
      setIsInviting(false);
    }
  };

  if (isLoading) {
    return <div className="flex items-center gap-2 text-slate-400"><Loader2 className="w-5 h-5 animate-spin"/> Loading team...</div>;
  }

  return (
    <div className="max-w-4xl">
      <h1 className="text-3xl font-bold mb-2 text-white">Team Management</h1>
      <p className="text-slate-400 mb-8">Manage organization members and their roles.</p>

      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 mb-8">
        <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <UserPlus className="h-5 w-5 text-slate-400" />
          Invite Member
        </h2>
        <form onSubmit={handleInvite} className="flex gap-4 items-end flex-wrap">
          <div className="flex-1 min-w-[200px]">
            <label htmlFor="email" className="block text-sm font-medium text-slate-400 mb-1">
              Email Address (User must have signed in once)
            </label>
            <input
              type="email"
              id="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="colleague@company.com"
            />
          </div>
          <div className="w-48">
            <label htmlFor="role" className="block text-sm font-medium text-slate-400 mb-1">
              Role
            </label>
            <select
              id="role"
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 text-white rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="admin">Admin</option>
              <option value="viewer">Viewer</option>
            </select>
          </div>
          <button
            type="submit"
            disabled={isInviting}
            className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium py-2 px-6 rounded-md transition-colors h-[42px]"
          >
            {isInviting ? 'Sending...' : 'Send Invite'}
          </button>
        </form>
        {message && <p className="mt-3 text-sm text-amber-400">{message}</p>}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-slate-950/50 border-b border-slate-800">
              <th className="py-3 px-6 text-sm font-medium text-slate-400">User ID</th>
              <th className="py-3 px-6 text-sm font-medium text-slate-400">Role</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {members.map((member, i) => (
              <tr key={member.id || i} className="hover:bg-slate-800/50 transition-colors">
                <td className="py-4 px-6">
                  <div className="flex items-center gap-3">
                    <div className="h-8 w-8 rounded-full bg-slate-800 flex items-center justify-center text-slate-300 font-medium uppercase">
                      {member.user_id.charAt(0)}
                    </div>
                    <div className="text-white font-medium text-sm font-mono truncate max-w-[200px]">
                      {member.user_id}
                    </div>
                  </div>
                </td>
                <td className="py-4 px-6">
                  <div className="flex items-center gap-2 capitalize">
                    {member.role === 'owner' && <ShieldAlert className="h-4 w-4 text-purple-400" />}
                    {member.role === 'admin' && <Shield className="h-4 w-4 text-blue-400" />}
                    {member.role === 'viewer' && <User className="h-4 w-4 text-slate-400" />}
                    <span className="text-sm text-slate-300">{member.role}</span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
