package com.y2gcoder.app.domain.member.repository;

import com.y2gcoder.app.domain.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {
}
